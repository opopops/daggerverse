from typing import Annotated, Self
import dataclasses
import dagger
from dagger import Doc, Name, dag, function, object_type

from .image import Image


@object_type
class Build:
    """Apko Build"""

    platform_variants: Annotated[list[dagger.Container], Doc("Platform variants")]
    tag: Annotated[str, Doc("Image tag")]
    apko: dagger.Container

    container_: dagger.Container = dataclasses.field(
        default_factory=lambda: dag.container()
    )

    @function
    def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticates with registry"""
        self.container_ = self.container_.with_registry_auth(
            address=address, username=username, secret=secret
        )
        return self

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Retrieves build platforms"""
        platforms: list[dagger.Platform] = []
        for platform_variant in self.platform_variants:
            platforms.append(await platform_variant.platform())
        return platforms

    @function(name="container")
    async def platform_container(
        self, platform: dagger.Platform | None = None
    ) -> dagger.Container:
        """Returns the build container"""
        platform = platform or await dag.default_platform()
        for platform_variant in self.platform_variants:
            if platform_variant.platform() == platform:
                return platform_variant

    @function
    def as_tarball(self) -> dagger.File:
        """Returns the image tarball"""
        return self.container_.as_tarball(platform_variants=self.platform_variants)

    @function
    def sbom(self) -> dagger.Directory:
        """Returns the SBOM directory"""
        return self.apko.directory("$APKO_SBOM_DIR", expand=True)

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
        self, tags: Annotated[list[str], Doc("Additional tags"), Name("tag")] = ()
    ) -> Image:
        """Publish multi-arch image"""
        await self.container_.publish(
            address=self.tag, platform_variants=self.platform_variants
        )
        # additionnal tags
        for tag in tags:
            await self.container_.publish(
                address=tag, platform_variants=self.platform_variants
            )
        return Image(address=self.tag, apko=self.apko)
