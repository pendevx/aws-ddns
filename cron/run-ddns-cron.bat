@echo off
:: remember to add environment variables
docker run --rm cron >> C:\logs\ddns-cron.log 2>&1
