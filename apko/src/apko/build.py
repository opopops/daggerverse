from typing import Annotated, Self

import dagger
from dagger import Doc, Name, dag, function, object_type

from .image import Image


@object_type
class Build:
    """Apko Build"""

    apko_: dagger.Container
    container_: dagger.Container
    platform_variants_: list[dagger.Container] | None

    @classmethod
    async def create(
        cls,
        apko: Annotated[dagger.Container, Doc("Apko container")],
        container: Annotated[dagger.Container, Doc("Image container")],
        platform_variants: Annotated[
            list[dagger.Container | None], Doc("Platform variants")
        ] = None,
    ):
        """Constructor"""
        return cls(
            apko_=apko, container_=container, platform_variants_=platform_variants
        )

    @function
    def apko(self) -> dagger.Container:
        """Returns the apko container"""
        return self.apko_

    @function
    def container(self) -> dagger.Container:
        """Returns the image container"""
        return self.container_

    def platform_variants(self) -> list[dagger.Container]:
        """Returns the image platform variants"""
        return self.platform_variants_

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Retrieves build platforms"""
        platforms: list[dagger.Platform] = [await self.container().platform()]
        for platform_variant in self.platform_variants():
            platforms.append(await platform_variant.platform())
        return platforms

    @function
    def as_directory(self) -> dagger.Directory:
        """Returns the build directory including image tarball and sbom dir"""
        return (
            dag.directory()
            .with_file("image.tar", self.as_tarball())
            .with_directory("sbom", self.sbom())
        )

    @function
    def as_tarball(self) -> dagger.File:
        """Returns the image tarball"""
        return self.container().as_tarball(platform_variants=self.platform_variants())

    @function
    def sbom(self) -> dagger.Directory:
        """Returns the SBOM directory"""
        return self.apko().directory("$APKO_SBOM_DIR", expand=True)

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticates with registry"""
        self.container_ = self.container().with_registry_auth(
            address=address, username=username, secret=secret
        )
        cmd = [
            "sh",
            "-c",
            (
                f"apko login {address}"
                f" --username {username}"
                " --password ${REGISTRY_PASSWORD}"
            ),
        ]
        self.apko_ = (
            self.apko()
            .with_secret_variable("REGISTRY_PASSWORD", secret)
            .with_exec(cmd, use_entrypoint=False)
        )
        return self

    @function
    def scan(
        self,
        severity_cutoff: (
            Annotated[
                str,
                Doc("Specify the minimum vulnerability severity to trigger an error"),
            ]
        ) = "",
        fail: Annotated[
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str, Doc("Report output formatter")] = "sarif",
    ) -> dagger.File:
        """Scan build result using Grype"""
        grype = dag.grype()
        return grype.scan_file(
            source=self.as_tarball(),
            source_type="oci-archive",
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
                Doc("Specify the minimum vulnerability severity to trigger an error"),
            ]
        ) = "",
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
        self, tags: Annotated[list[str], Doc("Image tags"), Name("tag")]
    ) -> Image:
        """Publish image"""
        # additionnal tags
        for tag in tags:
            await self.container().publish(
                address=tag, platform_variants=self.platform_variants()
            )
        return Image(address=tags[0], apko_=self.apko(), container_=self.container())
