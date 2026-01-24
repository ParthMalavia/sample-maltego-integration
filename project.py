import sys

import transforms
from extensions import registry
from maltego_trx.handler import handle_run
from maltego_trx.registry import register_transform_classes
from maltego_trx.server import app as application

register_transform_classes(transforms)

registry.write_transforms_config(include_output_entities=True)
registry.write_settings_config()


@application.route("/seed/")
def seed():
    return {
        "name": "Sample Maltego Integration",
        "transforms": [
            {
                "id": "domain_to_ip",
                "name": "Domain to IP",
                "input": "maltego.Domain",
                "endpoint": "/run/domain_to_ip",
            }
        ],
    }


if __name__ == "__main__":
    handle_run(__name__, sys.argv, application)
