#!/bin/bash


step=1
total_steps=3
max_retries=10 #seconds for the server reachability timeout

# if env variables are in place, default values are overridden
health_url="http://localhost:8001"
[[ ! -z "$HEALTH_URL" ]] && health_url=$HEALTH_URL
envoy_url_unfiltered="http://localhost:8001/home"
[[ ! -z "$REQ_UNFILTERED" ]] && envoy_url_unfiltered=$REQ_UNFILTERED
envoy_url_filtered="http://localhost:8001/admin"
[[ ! -z "$REQ_FILTERED" ]] && envoy_url_filtered=$REQ_FILTERED

# Testing if the server is up
echo "[$step/$total_steps] Testing application reachability"
status_code="000"
while [[ "$status_code" -eq "000" ]]; do
  status_code=$(curl --write-out "%{http_code}" --silent --output /dev/null $health_url)
  sleep 1
  echo -ne "[Wait] Waiting for response from $health_url. Timeout: ${max_retries}s   \r"
  ((max_retries-=1))
  if [[ "$max_retries" -eq 0 ]] ; then
    echo "[Fail] Timeout waiting for response from $health_url, make sure the server is running."
    exit 1
  fi
done
echo -e "\n[Ok] Got status code $status_code, expected 200. Ready to start."

# Testing envoy container reachability with an unfiltered request
((step+=1))
echo "[$step/$total_steps] Testing true negative request"
status_code=$(curl --write-out "%{http_code}" --silent --output /dev/null $envoy_url_unfiltered)
if [[ "$status_code" -ne 200 ]] ; then
  echo "[Fail] Unexpected response with code $status_code from $envoy_url_unfiltered"
  exit 1
fi
echo "[Ok] Got status code $status_code, expected 200"

# Testing filtered request
((step+=1))
echo "[$step/$total_steps] Testing true positive request"
status_code=$(curl --write-out "%{http_code}" --silent --output /dev/null $envoy_url_filtered)
if [[ "$status_code" -ne 403 ]] ; then
  echo "[Fail] Unexpected response with code $status_code from $envoy_url_filtered"
  exit 1
fi
echo "[Ok] Got status code $status_code, expected 403"

echo "[Done] All tests passed"
