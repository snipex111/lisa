from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Dict, List, Type

from dataclasses_json import dataclass_json

from lisa import schema
from lisa.sut_orchestrator.azure.tools import Waagent
from lisa.tools import Cat, Ls, Sed
from lisa.transformer import Transformer


@dataclass_json
@dataclass
class AzureHypervTransformerSchema(schema.Transformer):
    # SSH connection information to the node
    connection: Optional[schema.RemoteNode] = field(
        default=None, metadata=field_metadata(required=False)
    )



class AzureHypervTransformer(Transformer):
    """
    This Transformer prepares a marketplace image for lab testing.
    """

    @classmethod
    def type_name(cls) -> str:
        return "azure_hyperv"

    @classmethod
    def type_schema(cls) -> Type[schema.TypedSchema]:
        return AzureHypervTransformerSchema

    @property
    def _output_names(self) -> List[str]:
        return []

    def _internal_run(self) -> Dict[str, Any]:
        runbook: AzureHypervTransformerSchema = self.runbook
        assert isinstance(runbook, AzureHypervTransformerSchema)
        assert (
            runbook.connection
        ), "'connection' must be defined if not running during deployed phase."
        self._node = quick_connect(
            runbook.connection, runbook.name, parent_logger=self._log
        )
        node = self._node
        sed = node.tools[Sed]
        ls = node.tools[Ls]

        # node.tools[Waagent].deprovision()

        # Disable waagent and cloud-init
        # node.execute("touch /var/lib/waagent/disable_agent", sudo=True)
        # node.execute("touch /var/lib/waagent/provisioned", sudo=True)
        # node.execute("touch /etc/cloud/cloud-init.disabled", sudo=True)

        # Remove macaddress binding
        if ls.path_exists("/etc/netplan/50-cloud-init.yaml"):
            sed.delete_lines(
                "macaddress",
                PurePosixPath("/etc/netplan/50-cloud-init.yaml"),
                sudo=True,
            )

        # Remove 'earlycon' from kernel parameters
        # This is required by some ARM images
        node.tools[Cat].run("/etc/default/grub")
        cmdline = node.tools[Cat].run("/proc/cmdline").stdout
        self._log.debug(f"cmdline: {cmdline}")
        if "earlycon=" in cmdline:
            sed.substitute(
                "earlycon=\\S*\\s",
                "",
                "/etc/default/grub",
                sudo=True,
            )
            node.execute("grub2-mkconfig -o /boot/grub2/grub.cfg", sudo=True)

        return {}
