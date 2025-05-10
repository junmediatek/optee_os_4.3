
echo "Setting up mock build environment for HDCP 2.3 implementation..."

mkdir -p mock_ta_dev_kit/mk
touch mock_ta_dev_kit/mk/ta_dev_kit.mk
touch mock_ta_dev_kit/mk/conf.mk

mkdir -p mock_teec_export/include
mkdir -p mock_teec_export/lib

export TA_DEV_KIT_DIR=$(pwd)/mock_ta_dev_kit
export TEEC_EXPORT=$(pwd)/mock_teec_export

echo "Mock build environment set up."
echo "TA_DEV_KIT_DIR=$TA_DEV_KIT_DIR"
echo "TEEC_EXPORT=$TEEC_EXPORT"

echo "Running verification script..."
./verify_structure.sh

echo "Mock build verification completed."
