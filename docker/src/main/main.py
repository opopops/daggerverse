import asyncio
from typing import Annotated

import dagger
from dagger import Doc, Name, dag, field, function, object_type

from .build import Build


@object_type
class Docker:
    """Docker CLI"""

    registry: Annotated[str, Doc("Registry host")] | None = field(default="docker.io")
    username: Annotated[str, Doc("Registry username")] | None = field(default=None)
    password: Annotated[dagger.Secret, Doc("Registry password")] | None = field(
        default=None
    )

    def container(self, platform: dagger.Platform | None = None) -> dagger.Container:
        """Returns authentcated Docker container"""
        container: dagger.Container = dag.container(platform=platform)
        if self.username is not None and self.password is not None:
            container = container.with_registry_auth(
                address=self.registry, username=self.username, secret=self.password
            )
        return container

    @function
    async def build(
        self,
        context: Annotated[dagger.Directory, Doc("Dockerfile context")],
        platforms: Annotated[
            list[dagger.Platform],
            Doc("Set target platform for build"),
            Name("platform"),
        ] = (),
        dockerfile: Annotated[
            str, Doc("Name of the Dockerfile"), Name("file")
        ] = "Dockerfile",
        target: Annotated[str, Doc("Set the target build stage to build")] = "",
        build_args: Annotated[
            list[str],
            Doc("Build args to pass to the build in the format of name=value"),
            Name("build_arg"),
        ] = (),
        secrets: Annotated[
            list[dagger.Secret], Doc("Secrets to pass to the build"), Name("secret")
        ] = (),
    ) -> Build:
        """Build multi-arch OCI image"""
        platform_variants: list[dagger.Container] = []
        dagger_build_args: list[dagger.BuildArg] = []

        async def build_(
            container: dagger.Container,
            context: dagger.Directory,
            dockerfile: str,
            target: str,
            build_args: list[dagger.BuildArg],
            secrets: list[dagger.Secret],
        ):
            container = await container.build(
                context=context,
                dockerfile=dockerfile,
                target=target,
                build_args=build_args,
                secrets=secrets,
            )
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
                            container=self.container(platform=platform),
                            context=context,
                            dockerfile=dockerfile,
                            target=target,
                            build_args=dagger_build_args,
                            secrets=secrets,
                        )
                    )
        else:
            platform_variants.append(
                self.container().build(
                    context=context,
                    dockerfile=dockerfile,
                    target=target,
                    build_args=dagger_build_args,
                    secrets=secrets,
                )
            )
        return Build(
            platform_variants=platform_variants,
            registry=self.registry,
            username=self.username,
            password=self.password,
        )
