from typing import Annotated, Self
from urllib.parse import urlparse
import dagger
from dagger import Doc, Name, dag, function, object_type

from .image import Image


@object_type
class Build:
    """Apko Build module"""

    tarball: Annotated[dagger.File, Doc("Build Tarball")]
    archs: Annotated[list[dagger.Platform], Doc("Build Architecture"), Name("arch")]
    sbom: Annotated[dagger.Directory, Doc("SBOM directory")]
    tag: Annotated[str, Doc("Image tag")]
    docker_config: Annotated[dagger.File, Doc("Docker config file")]

    container_: dagger.Container | None = None
    crane_: dagger.Crane | None = None

    def registry(self) -> str:
        """Retrieves the registry host from tag"""
        url = urlparse(f"//{self.tag}")
        return url.netloc

    def crane(self) -> dagger.Crane:
        """Returns configured Crane"""
        if self.crane_:
            return self.crane_
        self.crane_: dagger.Crane = dag.crane(docker_config=self.docker_config)
        return self.crane_

    @function
    def container(
        self, platform: dagger.Platform | None = None, tag: str | None = None
    ) -> dagger.Container:
        """Returns the build container"""
        return dag.container(platform=platform).import_(self.tarball, tag=tag)

    @function
    def as_tarball(self) -> dagger.File:
        """Returns the image tarball"""
        return self.tarball

    @function
    def sbom_dir(self) -> dagger.Directory:
        """Returns the SBOM directory"""
        return self.sbom

    @function
    def build_dir(self) -> dagger.Directory:
        """Returns the build directory"""
        return (
            dag.directory()
            .with_file("image.tar", self.tarball)
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
        return grype.scan_file(
            source=self.tarball,
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
        self, tags: Annotated[list[str], Doc("Additional tags"), Name("tag")] = ()
    ) -> Image:
        """Publish multi-arch image"""
        platform_variants: list[dagger.Container] = []
        for arch in self.archs:
            platform_variants.append(self.container(platform=arch))
        await self.container_.publish(
            address=self.tag, platform_variants=platform_variants
        )
        # additionnal tags
        for tag in tags:
            await self.container_.publish(
                address=tag, platform_variants=platform_variants
            )
        return Image(address=self.tag, sbom=self.sbom, docker_config=self.docker_config)
