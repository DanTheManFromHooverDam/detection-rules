# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License
# 2.0; you may not use this file except in compliance with the Elastic License
# 2.0.

from . import common
from . import RtaMetadata


metadata = RtaMetadata(
    uuid="1ef908be-9ed3-413d-8d4d-94446107eecc",
    platforms=["macos", "linux"],
    endpoint=[
        {
            "rule_name": "Timestomping using Touch Command.",
            "rule_id": "b0046934-486e-462f-9487-0d4cf9e429c6",
        }
    ],
    siem=[],
    techniques=["T1070"],
)


@common.requires_os(metadata.platforms)
def main():

    masquerade = "/tmp/touch"
    if common.CURRENT_OS == "linux":
        source = common.get_path("bin", "linux.ditto_and_spawn")
        common.copy_file(source, masquerade)
    else:
        common.create_macos_masquerade(masquerade)

    ## Execute command
    common.log("Launching fake touch command to modify boot log last modification date")
    common.execute([masquerade,"-t","12141105","/var/log/boot.log"],timeout=10,kill=True)

    # cleanup
    common.remove_file(masquerade)


if __name__ == "__main__":
    exit(main())
