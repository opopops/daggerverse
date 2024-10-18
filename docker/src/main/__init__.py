"""Build, publish, scan and sign Docker images.

This module has been generated via dagger init and serves as a reference to
basic module structure as you get started with Dagger.
"""

import asyncio
import logging
import os
import json
from typing import Annotated, Self

import dagger
from dagger import Doc, dag, field, function, Name, object_type
from dagger.log import configure_logging

configure_logging(logging.INFO)


@object_type
class Docker:
    """Docker module"""

    digest: Annotated[str, Doc("image digest")] | None = field(default="")
    platform_variants: (
        Annotated[list[dagger.Container], Doc("platform variants")] | None
    ) = field(default=list)

    @function(name="import")
    def import_(
        self, address: Annotated[str, Doc("image address")]
    ) -> dagger.Container:
        """Import a Doker image"""
        container = dag.container().from_(address=address)
        self.digest = container.image_ref()
        return container

    @function(name="platforms")
    async def platforms_from_(
        self,
        address: Annotated[str, Doc("image address")],
        docker_image: Annotated[str, Doc("Docker CLI image")]
        | None = "chainguard/docker-cli:latest",
    ) -> list[dagger.Platform]:
        """Retrieve multi-arch image platforms"""
        platforms: list[dagger.Platform] = []
        container = dag.container().from_(docker_image)

        result = await container.with_exec(
            ["docker", "manifest", "inspect", address]
        ).stdout()

        manifest = json.loads(result)

        for entry in manifest.get("manifests", []):
            platform = entry["platform"]
            architecture = platform["architecture"]
            os = platform["os"]
            platforms.append(dagger.Platform(f"{os}/{architecture}"))
        return platforms

    async def platform_variants_from_(
        self, address: Annotated[str, Doc("image address")]
    ) -> list[dagger.Container]:
        """Retrieve multi-arch image platform variants"""
        platform_variants: list[dagger.Container] = []
        platforms = await self.platforms_from_(address=address)
        if platforms:
            for platform in platforms:
                container = dag.container(platform=platform).from_(address)
                platform_variants.append(container)
        else:
            platform_variants.append(dag.container().from_(address))
        return platform_variants

    @function
    async def apko(
        self,
        tag: Annotated[str, Doc("image tag")],
        context: Annotated[dagger.Directory, Doc("context directory")],
        arch: Annotated[str, Doc("architectures to build")] | None,
        config: Annotated[str, Doc("config file")] | None = "apko.yaml",
        apko_image: Annotated[str, Doc("apko docker image")]
        | None = "chainguard/apko:latest",
        shell_image: Annotated[str, Doc("shell docker image")]
        | None = "chainguard/bash:latest",
        user: Annotated[str, Doc("docker image user")] = "nonroot",
    ) -> Self:
        """Build multi-arch image using Chainguard apko tool"""
        apko = dag.container().from_(apko_image)
        shell = dag.container().from_(shell_image)
        cache_dir: str = "/tmp/apko/cache"
        builder = (
            shell.with_user(user)
            .with_mounted_directory(path="/work", source=context, owner=user)
            .with_mounted_cache(
                cache_dir,
                dag.cache_volume("APKO_CACHE"),
                sharing=dagger.CacheSharingMode("LOCKED"),
                owner=user,
            )
            .with_workdir(f"/work/{os.path.dirname(config)}")
            .with_file(path="/bin/apko", source=apko.file(path="/usr/bin/apko"))
            .with_entrypoint(["/bin/apko"])
        )

        async def apko_(arch: str = "host"):
            container: dagger.Container
            output_tar = "/tmp/image.tar"
            cmd = [
                "build",
                "--arch",
                arch,
                "--cache-dir",
                cache_dir,
                os.path.basename(config),
                tag,
                output_tar,
            ]
            self.tarball = await builder.with_exec(cmd, use_entrypoint=True).file(
                path=output_tar
            )
            if arch == "host":
                container = dag.container()
            else:
                platform = dagger.Platform(f"linux/{arch}")
                container = dag.container(platform=platform)
            self.platform_variants.append(container.import_(source=self.tarball))

        if arch is not None:
            async with asyncio.TaskGroup() as tg:
                for arch_ in arch.split(","):
                    tg.create_task(apko_(arch=arch_))
        else:
            await apko_()

        return self

    @function
    async def build(
        self,
        context: Annotated[dagger.Directory, Doc("Dockerfile context")],
        platform: Annotated[str, Doc("container platforms")] | None,
        dockerfile: Annotated[str, Doc("path to the Dockerfile")] | None = "Dockerfile",
        target: Annotated[str, Doc("stage to build")] | None = "",
    ) -> Self:
        """Build multi-arch image using Dockerfile"""

        async def build_(
            container: dagger.Container,
            context: dagger.Directory,
            dockerfile: str,
            target: str,
        ):
            container = await container.build(
                context=context, dockerfile=dockerfile, target=target
            )
            self.platform_variants.append(container)

        if platform is not None:
            platforms = [
                dagger.Platform(platform_) for platform_ in platform.split(",")
            ]
            async with asyncio.TaskGroup() as tg:
                for platform in platforms:
                    tg.create_task(
                        build_(
                            container=dag.container(platform=platform),
                            context=context,
                            dockerfile=dockerfile,
                            target=target,
                        )
                    )
        else:
            self.platform_variants.append(
                dag.container().build(
                    context=context, dockerfile=dockerfile, target=target
                )
            )
        return self

    @function
    async def export(
        self,
        address: (Annotated[str, Doc("image address")]) | None,
        compress: Annotated[bool, Doc("enable compression")] | None = False,
    ) -> dagger.File:
        """Export image as tarball"""
        if address is not None:
            container = dag.container(address=address)
            image_ref = await container.image_ref()
            image_tag = image_ref.split("@")[0]
            self.platform_variants = await self.platform_variants_from_(
                address=image_tag
            )
        forced_compression = dagger.ImageLayerCompression("Uncompressed")
        if compress:
            forced_compression = dagger.ImageLayerCompression("Gzip")
        tarball = dag.container().as_tarball(
            forced_compression=forced_compression,
            platform_variants=self.platform_variants,
        )
        return tarball

    @function
    async def publish(
        self,
        tags: Annotated[list[str], Doc("image tag"), Name("tag")],
        address: (Annotated[str, Doc("image address to publish")]) | None,
        username: Annotated[str, Doc("registry username")] | None,
        password: Annotated[dagger.Secret, Doc("registry password")] | None,
    ) -> Self:
        """Publish multi-arch image"""
        if address is not None:
            # Retrieve platform variants for specififed address
            container = dag.container(address)
            image_ref = await container.image_ref()
            if address == image_ref:
                self.platform_variants = [container]
            else:
                image_tag = image_ref.split("@")[0]
                self.platform_variants = await self.platform_variants_from_(
                    address=image_tag
                )

        for tag in tags:
            container_ = dag.container()
            if username is not None and password is not None:
                container_ = container_.with_registry_auth(
                    address=tag, username=username, secret=password
                )
            digest_ = await container_.publish(
                address=tag, platform_variants=self.platform_variants
            )
            if not self.digest:
                self.digest = digest_
        return self

    @function
    async def sign(
        self,
        private_key: Annotated[dagger.Secret, Doc("cosign private key")],
        password: Annotated[dagger.Secret, Doc("cosign password")],
        digest: (Annotated[str, Doc("image digest")]) | None,
        registry_username: Annotated[str, Doc("registry username")] | None = None,
        registry_password: (
            Annotated[dagger.Secret, Doc("registry password")] | None
        ) = None,
        docker_config: Annotated[dagger.File, Doc("docker config")] | None = None,
        cosign_image: Annotated[str, Doc("cosign image")] = "chainguard/cosign:latest",
        cosign_user: Annotated[str, Doc("cosign image user")] = "nonroot",
    ) -> str:
        """Sign multi-arch image with Cosign"""

        if digest is not None:
            self.digest = digest

        cmd = ["sign", self.digest, "--key", "env://COSIGN_PRIVATE_KEY"]

        if registry_username and registry_password:
            cmd.extend(
                [
                    "--registry-username",
                    registry_username,
                    "--registry-password",
                    await registry_password.plaintext(),
                ]
            )

        container = (
            dag.container()
            .from_(cosign_image)
            .with_user(cosign_user)
            .with_env_variable("DOCKER_CONFIG", "/tmp/docker")
            .with_env_variable("COSIGN_YES", "true")
            .with_secret_variable("COSIGN_PASSWORD", password)
            .with_secret_variable("COSIGN_PRIVATE_KEY", private_key)
            .with_exec(cmd, use_entrypoint=True)
        )

        if docker_config:
            container = container.with_mounted_file(
                "/tmp/docker/config.json", docker_config, owner=cosign_user
            )

        return await container.stdout()

    @function
    async def scan(
        self,
        address: Annotated[str, Doc("image to scan")] | None,
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
        output_format: Annotated[str, Doc("Report output formatter")] = "table",
        grype_image: Annotated[str, Doc("Grype image")] = "chainguard/grype:latest",
        grype_user: Annotated[str, Doc("Grype image user")] = "nonroot",
    ) -> str:
        """Scan image with Grype and return the formatted report"""
        tarball: dagger.File = None
        cache_dir: str = "/tmp/.grype/cache"
        image_tar = "/tmp/image.tar"

        cmd = [image_tar, "--output", output_format]
        if fail_on:
            cmd.extend(["--fail-on", fail_on])

        if address is not None or self.digest:
            if address is not None:
                self.digest = address
            tarball = dag.container().from_(address=self.digest).as_tarball()
        else:
            tarball = dag.container().as_tarball(
                platform_variants=self.platform_variants
            )

        return await (
            dag.container()
            .from_(grype_image)
            .with_user(grype_user)
            .with_env_variable("GRYPE_DB_CACHE_DIR", cache_dir)
            .with_mounted_cache(
                cache_dir,
                dag.cache_volume("GRYPE_DB_CACHE"),
                sharing=dagger.CacheSharingMode("LOCKED"),
                owner=grype_user,
            )
            .with_file(path=image_tar, source=tarball, owner=grype_user)
            .with_exec(cmd, use_entrypoint=True)
            .stdout()
        )
