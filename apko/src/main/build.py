from typing import Annotated, Self
from urllib.parse import urlparse
import dagger
from dagger import Doc, dag, function, object_type

from .image import Image


@object_type
class Build:
    """Apko Build module"""

    directory: Annotated[dagger.Directory, Doc("APKO OCI directory")]
    tag: Annotated[str, Doc("Image tag")]

    credentials_: list[tuple[str, str, dagger.Secret]] | None = None
    crane_: dagger.Crane | None = None

    def registry(self) -> str:
        """Retrieves the registry host from tag"""
        url = urlparse(f"//{self.tag}")
        return url.netloc

    def crane(self) -> dagger.Crane:
        """Returns configured Crane"""
        if self.crane_:
            return self.crane_
        self.crane_: dagger.Crane = dag.crane()
        for credential in self.credentials_ or []:
            self.crane_ = self.crane_.with_registry_auth(
                address=credential[0], username=credential[1], secret=credential[2]
            )
        return self.crane_

    @function
    def sbom(self) -> dagger.Directory:
        """Returns SBOM"""
        return self.directory.wihtout_file("image.tar")

    @function
    def oci_dir(self) -> dagger.Directory:
        """Returns the image OCI layout directory"""
        return self.directory

    @function
    def scan(
        self,
        fail_on: (
            Annotated[
                str,
                Doc(
                    """Set the return code to 1 if a vulnerability is found
                    with a severity >= the given severity"""
                ),
            ]
            | None
        ) = None,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> dagger.File:
        """Scan build result using Grype"""
        grype = dag.grype()
        return grype.scan_directory(
            source=self.directory,
            source_type="oci-dir",
            fail_on=fail_on,
            output_format=output_format,
        )

    @function
    def with_scan(
        self,
        fail_on: (
            Annotated[
                str,
                Doc(
                    """Set the return code to 1 if a vulnerability is found
                    with a severity >= the given severity"""
                ),
            ]
            | None
        ) = None,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> Self:
        """Scan build result using Grype (for chaining)"""
        self.scan(fail_on=fail_on, output_format=output_format)
        return self

    @function
    async def publish(
        self,
        registry_username: Annotated[str, Doc("Registry username")] | None = None,
        registry_password: Annotated[dagger.Secret, Doc("Registry password")]
        | None = None,
    ) -> Image:
        """Publish multi-arch image"""
        if registry_username and registry_password:
            if self.credentials_:
                self.credentials_.append(
                    (self.registry(), registry_username, registry_password)
                )
            else:
                self.credentials_ = [
                    (self.registry(), registry_username, registry_password)
                ]
        ref: str = await self.crane().push(path=self.directory, image=self.tag, index=True)
        return Image(address=ref, credentials_=self.credentials_)
