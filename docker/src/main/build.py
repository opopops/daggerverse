from typing import Annotated, Self
import dagger
from dagger import Doc, Name, dag, function, object_type

from .cli import Cli as DockerCli
from .image import Image


@object_type
class Build:
    """Docker Build"""

    container_: dagger.Container
    platform_variants: list[dagger.Container]

    docker: DockerCli

    @function
    def as_tarball(self) -> dagger.File:
        """Returns the build as tarball"""
        return self.container.as_tarball(platform_variants=self.platform_variants)

    @function
    async def container(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.Container:
        """Returns the container for the specified platform (current platform if not specified)"""
        if platform:
            if platform == await self.container.platform():
                return self.container_
            for platform_variant in self.platform_variants:
                if await platform_variant.platform() == platform:
                    return platform_variant
        return self.container_

    @function
    async def tarball(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Returns the container tarball for the specified platform"""
        container: dagger.Container = await self.container(platform=platform)
        return container.as_tarball()

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Retrieves build platforms"""
        platforms: list[dagger.Platform] = [await self.container_.platform()]
        for platform_variant in self.platform_variants:
            platforms.append(await platform_variant.platform())
        return platforms

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
        address: str = ""
        # additionnal tags
        for tag in tags:
            address = await self.container_.publish(
                address=tag, platform_variants=self.platform_variants
            )
        return Image(address=address, container_=self.container_, docker=self.docker)
