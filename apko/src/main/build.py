from typing import Annotated, Self
from urllib.parse import urlparse
import dagger
from dagger import Doc, Name, dag, function, object_type

from .image import Image


@object_type
class Build:
    """Apko Build module"""

    oci: Annotated[dagger.Directory, Doc("OCI directory")]
    sbom: Annotated[dagger.Directory, Doc("SBOM directory")]
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
    def oci_dir(self) -> dagger.Directory:
        """Returns the OCI directory"""
        return self.oci

    @function
    def sbom_dir(self) -> dagger.Directory:
        """Returns the SBOM directory"""
        return self.sbom

    @function
    def build_dir(self) -> dagger.Directory:
        """Returns the build directory"""
        return (
            dag.directory()
            .with_directory("oci", self.oci)
            .with_directory("sbom", self.sbom)
        )

    @function
    def scan(
        self,
        severity_cutoff: (
            Annotated[
                str,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> dagger.File:
        """Scan build result using Grype"""
        grype = dag.grype()
        return grype.scan_directory(
            source=self.oci,
            source_type="oci-dir",
            severity_cutoff=severity_cutoff,
            fail=fail,
            output_format=output_format,
        )

    @function
    def with_scan(
        self,
        severity_cutoff: (
            Annotated[
                str,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> Self:
        """Scan build result using Grype (for chaining)"""
        self.scan(
            severity_cutoff=severity_cutoff, fail=fail, output_format=output_format
        )
        return self

    @function
    async def publish(
        self,
        tags: Annotated[list[str], Doc("Additional tags"), Name("tag")] = (),
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
        await self.crane().push(path=self.oci, image=self.tag, index=True)
        # additionnal tags
        for tag in tags:
            await self.crane().copy(source=self.tag, target=tag)
        return Image(address=self.tag, sbom=self.sbom, credentials_=self.credentials_)
