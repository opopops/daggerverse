import asyncio
from typing import Annotated, Self

import dagger
from dagger import DefaultPath, Doc, Name, dag, function, object_type

from .build import Build


@object_type
class Docker:
    """Docker"""

    container: dagger.Container | None = None

    @classmethod
    async def create(cls):
        """Constructor"""
        return cls(container=dag.container())

    @function
    async def with_registry_auth(
        self,
        username: Annotated[str, Doc("Registry username")],
        secret: Annotated[dagger.Secret, Doc("Registry password")],
        address: Annotated[str | None, Doc("Registry host")] = "docker.io",
    ) -> Self:
        """Authenticate with registry"""
        self.container = self.container.with_registry_auth(
            address=address, username=username, secret=secret
        )
        return self

    @function
    async def build(
        self,
        context: Annotated[dagger.Directory | None, DefaultPath("."), Doc("Context")],
        dockerfile: Annotated[
            str | None, Doc("Location of the Dockerfile")
        ] = "Dockerfile",
        target: Annotated[str | None, Doc("Set the target build stage to build")] = "",
        build_args: Annotated[
            list[str] | None,
            Doc("Build args to pass to the build in the format of name=value"),
            Name("build_arg"),
        ] = (),
        secrets: Annotated[
            list[dagger.Secret] | None,
            Doc("Secrets to pass to the build"),
            Name("secret"),
        ] = (),
        platforms: Annotated[
            list[dagger.Platform] | None,
            Doc("Set target platform for build"),
            Name("platform"),
        ] = (),
    ) -> Build:
        """Build multi-arch OCI image"""
        current_platform: dagger.Platform = await self.container.platform()
        platform_variants: list[dagger.Container] = []
        dagger_build_args: list[dagger.BuildArg] = []

        async def build_(
            platform: dagger.Platform,
            context: dagger.Directory,
            dockerfile: str,
            target: str,
            build_args: list[dagger.BuildArg],
            secrets: list[dagger.Secret],
        ):
            container: dagger.Container = dag.container(platform=platform)
            if platform == current_platform:
                container = self.container

            container = await container.build(
                context=context,
                dockerfile=dockerfile,
                target=target,
                build_args=build_args,
                secrets=secrets,
            )
            if platform == current_platform:
                self.container = container
            else:
                platform_variants.append(container)

        for build_arg in build_args:
            build_arg_split = build_arg.split("=")
            dagger_build_args.append(
                dagger.BuildArg(name=build_arg_split[0], value=build_arg_split[1])
            )

        if platforms:
            async with asyncio.TaskGroup() as tg:
                for platform in platforms:
                    tg.create_task(
                        build_(
                            platform=platform,
                            context=context,
                            dockerfile=dockerfile,
                            target=target,
                            build_args=dagger_build_args,
                            secrets=secrets,
                        )
                    )
        else:
            self.container = self.container.build(
                context=context,
                dockerfile=dockerfile,
                target=target,
                build_args=dagger_build_args,
                secrets=secrets,
            )
        return Build(platform_variants_=platform_variants, container_=self.container)
