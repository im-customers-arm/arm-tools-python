import time

from pathlib import Path

from deepdiff import DeepDiff
from spdx_tools.spdx3.deserialize.deserializer import parse_file

def deserialize_file(file_path):
    """Test the high-level deserializer API."""
    
    try:
        spdx_v3_payload = parse_file(file_path, validate=False)

        # This Payload structure contains a map of spdxID -> spdxElement.
        # This is the same data structure used to convert v2 documents into the v3 objects.
        sbom = spdx_v3_payload.get_full_map()

        return sbom
    except Exception as e:
        print(f"Error during deserialization: {e}")

def get_path(file_name: str) -> Path:
    return Path(__file__).parent / "sboms" / file_name

file_names = [
    ["zephyr-siva_arm_Unlicensed_10.jsonld.json", "zephyr-siva_arm_Unlicensed_10_2.jsonld.json"],
    ["zephyr-siva_arm_Unlicensed_100.jsonld.json", "zephyr-siva_arm_Unlicensed_100_2.jsonld.json"],
    ["zephyr-siva_arm_Unlicensed_1000.jsonld.json", "zephyr-siva_arm_Unlicensed_1000_2.jsonld.json"],
    ["zephyr-siva_arm_Unlicensed_10000.jsonld.json", "zephyr-siva_arm_Unlicensed_10000_2.jsonld.json"],
    ["zephyr-siva_arm_Unlicensed_12000.jsonld.json", "zephyr-siva_arm_Unlicensed_12000_2.jsonld.json"],
    ["zephyr-siva_arm_Unlicensed_15000.jsonld.json", "zephyr-siva_arm_Unlicensed_15000_2.jsonld.json"],
    ["zephyr-siva_arm_Unlicensed_20000.jsonld.json", "zephyr-siva_arm_Unlicensed_20000_2.jsonld.json"],
    ["zephyr-siva_arm_Unlicensed_25000.jsonld.json", "zephyr-siva_arm_Unlicensed_25000_2.jsonld.json"],
    ["zephyr-siva_arm_Unlicensed_50000.jsonld.json", "zephyr-siva_arm_Unlicensed_50000_2.jsonld.json"],
    ["zephyr-siva_arm_Unlicensed.jsonld.json", "zephyr-siva_arm_Unlicensed_2.jsonld.json"]
]

for file_name_pair in file_names:
    file0 = file_name_pair[0]
    file1 = file_name_pair[1]
    path1 = get_path(file0)
    path2 = get_path(file1)

    obj1 = deserialize_file(path1)
    obj2 = deserialize_file(path2)

    # Semantic diff
    # diff = DeepDiff(obj1, obj2, ignore_order=True, view='tree', verbose_level=1)
    start_time = time.time()
    diff = DeepDiff(obj1, obj2, ignore_order=True)
    end_time = time.time()

    elapsed_ms = (end_time - start_time) * 1000
    print(f"Time to diff {file0} and {file1}: {elapsed_ms:.2f} ms")
    # print("Printing diff:")
    # print(diff.pretty())

print("Done")
