from typing import Annotated

import dagger
from dagger import Doc, dag, function, object_type


@object_type
class Sbom:
    """SBOM files"""

    directory_: dagger.Directory

    @function
    def directory(self) -> dagger.Directory:
        """Returns the SBOM directory"""
        return self.directory_

    @function
    async def file(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Returns the SBOM file for the specified platform (current platform if not specified)"""
        if platform is None:
            platform = await dag.default_platform()
        return self.directory_.file(f"sbom-{platform.replace('/', '-')}.spdx.json")
