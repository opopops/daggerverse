from typing import Annotated

import dagger
from dagger import Doc, function, object_type


@object_type
class Sbom:
    """SBOM files"""

    directory_: dagger.Directory

    @function
    def directory(self) -> dagger.Directory:
        """Returns the SBOM directory"""
        return self.directory_

    @function
    def file(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Returns the SBOM file for the specified platform (index if not specified)"""
        if platform is not None:
            if platform == dagger.Platform("linux/amd64"):
                return self.directory_.file("sbom-x86_64.spdx.json")
            return self.directory_.file("sbom-aarch64.spdx.json")
        return self.directory_.file("sbom-index.spdx.json")
