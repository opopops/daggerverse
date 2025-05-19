import json
from typing import Annotated, Self
from urllib.parse import urlparse

import dagger
from dagger import Doc, dag, field, function, object_type

from .cli import Cli as DockerCli


@object_type
class Image:
    """Docker Image"""

    address: str = field()
    container_: dagger.Container

    docker: DockerCli

    def docker_config(self) -> dagger.File:
        """Returns the docker config file"""
        return self.docker.container().file("${DOCKER_CONFIG}/config.json", expand=True)

    def crane(self) -> dagger.Crane:
        """Returns crane"""
        return dag.crane(docker_config=self.docker_config())

    def cosign(self) -> dagger.Cosign:
        """Returns cosign"""
        return dag.cosign(docker_config=self.docker_config())

    def grype(self) -> dagger.Grype:
        """Returns grype"""
        return dag.grype(docker_config=self.docker_config())

    @function
    async def container(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.Container:
        """Returns the container for the specified platform (current platform if not specified)"""
        if platform:
            if platform == await self.container_.platform():
                return self.container_
            return dag.container(platform=platform).from_(address=self.address)
        return self.container_

    @function
    def tarball(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> dagger.File:
        """Returns the container tarball for the specified platform"""
        container: dagger.Container = self.container(platform=platform)
        return container.as_tarball()

    @function
    async def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str | None, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticate with registry"""
        self.container_ = self.container_.with_registry_auth(
            address=address, username=username, secret=secret
        )
        self.docker = self.docker.with_registry_auth(
            address=address, username=username, secret=secret
        )
        return self

    @function
    async def platforms(self) -> list[dagger.Platform]:
        """Retrieves image platforms"""
        platforms: list[dagger.Platform] = []
        manifest = json.loads(await self.crane().manifest(image=self.address))
        for entry in manifest.get("manifests", []):
            platform = entry["platform"]
            architecture = platform["architecture"]
            os = platform["os"]
            platforms.append(dagger.Platform(f"{os}/{architecture}"))
        return platforms

    @function
    async def ref(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> str:
        """Retrieves the fully qualified image ref"""
        ref = await self.crane().digest(
            image=self.address, platform=platform, full_ref=True
        )
        return ref.strip()

    @function
    async def digest(
        self, platform: Annotated[dagger.Platform | None, Doc("Platform")] = None
    ) -> str:
        """Retrieves the image digest"""
        digest = await self.crane().digest(image=self.address, platform=platform)
        return digest.strip()

    @function
    async def registry(self) -> str:
        """Retrieves the registry host from image address"""
        url = urlparse(f"//{await self.ref()}")
        return url.netloc

    @function
    async def tag(self, tag: Annotated[str, Doc("Tag")]) -> str:
        """Tag image"""
        return await self.crane().tag(image=self.address, tag=tag)

    @function
    async def with_tag(self, tag: Annotated[str, Doc("Tag")]) -> Self:
        """Tag image (for chaining)"""
        await self.tag(tag=tag)
        return self

    @function
    async def copy(self, target: Annotated[str, Doc("Target")]) -> str:
        """Copy image to another registry"""
        result = await self.cosign().copy(
            source=self.address, destination=target, force=True
        )
        return result

    @function
    async def with_copy(self, target: Annotated[str, Doc("Target")]) -> Self:
        """Copy image to another registry (for chaining)"""
        await self.copy(target=target)
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
            bool, Doc("Set to false to avoid failing based on severity-cutoff")
        ] = True,
        output_format: Annotated[str | None, Doc("Report output formatter")] = "table",
    ) -> dagger.File:
        """Scan image using Grype"""
        return self.grype().scan_image(
            source=self.address,
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
        """Scan image using Grype (for chaining)"""
        report: dagger.File = self.scan(
            severity_cutoff=severity_cutoff, fail=fail, output_format=output_format
        )
        await report.contents()
        return self

    @function
    async def sign(
        self,
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")]
        | None = None,
        password: Annotated[dagger.Secret | None, Doc("Cosign password")] | None = None,
        oidc_provider: Annotated[
            str | None, Doc("Specify the provider to get the OIDC token from")
        ]
        | None = None,
        oidc_issuer: Annotated[
            str | None, Doc("OIDC provider to be used to issue ID toke")
        ]
        | None = None,
        recursive: Annotated[
            bool | None,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ]
        | None = True,
    ) -> str:
        """Sign image with Cosign"""
        return await self.cosign().sign(
            image=await self.ref(),
            private_key=private_key,
            password=password,
            oidc_provider=oidc_provider,
            oidc_issuer=oidc_issuer,
            recursive=recursive,
        )

    @function
    async def with_sign(
        self,
        private_key: Annotated[dagger.Secret | None, Doc("Cosign private key")]
        | None = None,
        password: Annotated[dagger.Secret | None, Doc("Cosign password")] | None = None,
        oidc_provider: Annotated[
            str | None, Doc("Specify the provider to get the OIDC token from")
        ]
        | None = None,
        oidc_issuer: Annotated[
            str | None, Doc("OIDC provider to be used to issue ID toke")
        ]
        | None = None,
        recursive: Annotated[
            bool | None,
            Doc(
                "If a multi-arch image is specified, additionally sign each discrete image"
            ),
        ]
        | None = True,
    ) -> Self:
        """Sign image with Cosign (for chaining)"""
        await self.sign(
            private_key=private_key,
            password=password,
            oidc_provider=oidc_provider,
            oidc_issuer=oidc_issuer,
            recursive=recursive,
        )
        return self
