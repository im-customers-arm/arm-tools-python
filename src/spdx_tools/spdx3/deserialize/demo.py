import sys
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("spdx-parser-driver")


# Import our SPDX v3 parser components
try:
    from spdx_tools.spdx3.deserialize.deserializer import parse_anything, parse_file, parse_json_string

except ImportError as e:
    logger.error(f"Error importing SPDX modules: {e}")
    logger.error("Make sure you've installed the package or are running from the correct directory")
    sys.exit(1)


def run_deserializer(file_path, validate=False):
    """Test the high-level deserializer API."""
    logger.info("Testing the SPDX v3 deserializer API...")
    
    try:
        # Try to parse a file if provided
        logger.info(f"Parsing file: {file_path}")

        spdx_v3_payload = parse_anything(file_path, validate)

        # This Payload structure contains a map of spdxID -> spdxElement.
        # This is the same data structure used to convert v2 documents into the v3 objects.
        sbom_map = spdx_v3_payload.get_full_map()
        logger.info("Successfully deserialized document")
        logger.info("Inspecting map:")
        for key in sbom_map:
            logger.info("key:")
            logger.info(key)
            logger.info("value")
            logger.info(sbom_map[key])
                    
        return True
    except Exception as e:
        logger.error(f"Error during deserialization: {e}")
        return False


"""Main function to demonstrate the SPDX v3 deserializer."""
logger.info("SPDX v3 Deserializer Driver")
logger.info("====================")


small_jsonld_file_path = Path(__file__).parent / "sboms" / "small.jsonld"
# zephyr_jsonld_file_path = Path(__file__).parent / "sboms" / "zephyr.spdx.jsonld"
# zephyr_jsonld_file_path = Path(__file__).parent / "sboms" / "zephyr_fixed_after_iteratitive_agentic_edits.jsonld"
# zephyr_jsonld_file_path = Path(__file__).parent / "sboms" / "zephyr_modified_with_ai.jsonld"
zephyr_jsonld_file_path = Path(__file__).parent / "sboms" / "zephyr-siva_arm_Unlicensed_10.jsonld.json"


# deserializer_ok = run_deserializer(small_jsonld_file_path, validate=True)
# if deserializer_ok:
#     logger.info(f"Deserializer completed successfully for file {str(small_jsonld_file_path)}")

# This worked.
# deserializer_ok = run_deserializer(zephyr_jsonld_file_path, validate=False)
# TODO: consider whether it makes sense to remove validation check altogether.
# This might be unnecessary responsibility for the parser/deserializer.
# Arguably the responsibility of the SBOM-generating process.
deserializer_ok = run_deserializer(zephyr_jsonld_file_path, validate=False)
if deserializer_ok:
    logger.info(f"Deserializer completed successfully for file {str(zephyr_jsonld_file_path)}")
    



if not deserializer_ok:
    logger.warning("Failed, see logs for details")
    sys.exit(1)
