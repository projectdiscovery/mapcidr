#!/bin/bash

echo "::group::Build mapcidr"
cd ../cmd/mapcidr
go build
mv mapcidr ../../integration_tests/mapcidr
echo "::endgroup::"
echo "::group::Build mapcidr integration-test"
cd ../integration-test
go build
cp -rf goldenfiles ../../integration_tests/
mv integration-test ../../integration_tests/integration-test
cd ../../integration_tests
echo "::endgroup::"
./integration-test
if [ $? -eq 0 ]
then
  rm integration-test mapcidr 2>/dev/null
else
  rm integration-test mapcidr 2>/dev/null
  exit 1
fi

echo "::group::Build mapcidr integration-test-as-library"
cd ../cmd/integration-test-as-library
go build
mv integration-test-as-library ../../integration_tests/integration-test-as-library
cd ../../integration_tests
echo "::endgroup::"
./integration-test-as-library 
if [ $? -eq 0 ]
then
  rm integration-test-as-library >/dev/null
  exit 0
else
  rm integration-test-as-library >/dev/null
  exit 1
fi
