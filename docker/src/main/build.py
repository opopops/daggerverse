from typing import Annotated, Self
import dagger
from dagger import Doc, Name, dag, function, object_type

from .image import Image


@object_type
class Build:
    """Docker Build"""

    container_: dagger.Container
    platform_variants_: list[dagger.Container] | None

    @classmethod
    async def create(
        cls,
        container: Annotated[dagger.Container, Doc("Container")],
        platform_variants: Annotated[
            list[dagger.Container | None], Doc("Platform variants")
        ] = None,
    ):
        """Constructor"""
        return cls(container_=container, platform_variants_=platform_variants)

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Retrieves build platforms"""
        platforms: list[dagger.Platform] = [await self.container_.platform()]
        for platform_variant in self.platform_variants_:
            platforms.append(await platform_variant.platform())
        return platforms

    @function()
    async def container(self) -> dagger.Container:
        """Returns the current host platform variant container"""
        return self.container_

    @function
    async def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticate with registry"""
        self.container_ = self.container_.with_registry_auth(
            address=address, username=username, secret=secret
        )
        return self

    @function
    def as_tarball(
        self, compress: Annotated[bool | None, Doc("Enable compression")] = False
    ) -> dagger.File:
        """Export container as tarball"""
        forced_compression = dagger.ImageLayerCompression("Uncompressed")
        if compress:
            forced_compression = dagger.ImageLayerCompression("Gzip")
        return self.container_.as_tarball(
            platform_variants=self.platform_variants_,
            forced_compression=forced_compression,
        )

    @function
    def scan(
        self,
        severity_cutoff: (
            Annotated[
                str | None,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str | None, Doc("Report output formatter")] = "table",
    ) -> dagger.File:
        """Scan build result using Grype"""
        return dag.grype().scan_file(
            source=self.container_.as_tarball(),
            source_type="oci-archive",
            severity_cutoff=severity_cutoff,
            fail=fail,
            output_format=output_format,
        )

    @function
    async def with_scan(
        self,
        severity_cutoff: (
            Annotated[
                str | None,
                Doc(
                    """Specify the minimum vulnerability severity to trigger an "error" level ACS result"""
                ),
            ]
            | None
        ) = None,
        fail: Annotated[
            bool | None, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str | None, Doc("Report output formatter")] = "table",
    ) -> Self:
        """Scan build result using Grype (for chaining)"""
        report: dagger.File = self.scan(
            severity_cutoff=severity_cutoff, fail=fail, output_format=output_format
        )
        await report.contents()
        return self

    @function
    async def publish(
        self, tags: Annotated[list[str], Doc("Image tags"), Name("tag")]
    ) -> Image:
        """Publish image"""
        # additionnal tags
        for tag in tags:
            await self.container_.publish(
                address=tag, platform_variants=self.platform_variants_
            )
        return Image(address=tags[0], container_=self.container_)
