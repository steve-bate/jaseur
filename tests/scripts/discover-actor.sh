#!/bin/bash

# Exit on error, but not if jq fails
set +e

if [ -z "$1" ]; then
    echo "Usage: $0 acct:username@domain"
    exit 1
fi

ACCT="$1"
DOMAIN=$(echo "$ACCT" | cut -d@ -f2)

echo "Performing WebFinger lookup for $ACCT..."
WEBFINGER_URL="https://${DOMAIN}/.well-known/webfinger?resource=${ACCT}"
WEBFINGER_DATA=$(curl -s "$WEBFINGER_URL")

echo -e "\nWebFinger Response:"
if ! echo "$WEBFINGER_DATA" | jq '.' > /dev/null 2>&1; then
    echo "Raw response (not valid JSON):"
    echo "$WEBFINGER_DATA"
else
    echo "$WEBFINGER_DATA" | jq '.'
fi

# Extract the self link from WebFinger response
ACTOR_URL=$(echo "$WEBFINGER_DATA" | jq -r '.links[] | select(.rel=="self") | .href' 2>/dev/null)

if [ -z "$ACTOR_URL" ]; then
    echo "Error: Could not find actor URL in WebFinger response"
    exit 1
fi

echo -e "\nFetching actor data from $ACTOR_URL..."
ACTOR_DATA=$(curl -s -H "Accept: application/activity+json" "$ACTOR_URL")

echo "'$ACTOR_DATA'"
echo -e "\nActor Data:"
if ! echo "$ACTOR_DATA" | jq '.' > /dev/null 2>&1; then
    echo "Raw response (not valid JSON):"
    echo "$ACTOR_DATA"
else
    echo "$ACTOR_DATA" | jq '.'
fi