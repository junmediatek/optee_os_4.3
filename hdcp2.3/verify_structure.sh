#!/bin/bash
echo 'Verifying HDCP 2.3 implementation structure...'
# Check TA directory structure
if [ -d 'ta' ] && [ -d 'ta/include' ] && [ -d 'ta/src' ]; then
  echo 'TA directory structure: OK'
else
  echo 'TA directory structure: FAIL'
fi
# Check CA directory structure
if [ -d 'ca' ] && [ -d 'ca/include' ] && [ -d 'ca/src' ]; then
  echo 'CA directory structure: OK'
else
  echo 'CA directory structure: FAIL'
fi
# Check key files
files_to_check=(
  'ta/include/hdcp2_3_ta.h'
  'ta/src/entry.c'
  'ca/include/hdcp_ca.h'
  'ca/src/hdcp_ca.c'
)
missing_files=0
for file in "${files_to_check[@]}"; do
  if [ ! -f "$file" ]; then
    echo "Missing file: $file"
    missing_files=1
  fi
done
if [ $missing_files -eq 0 ]; then
  echo 'Key files: OK'
else
  echo 'Key files: FAIL'
fi
