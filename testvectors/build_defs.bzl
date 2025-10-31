"""Macro for working with Wycheproof test vectors."""

def _filter_vectors_impl(ctx):
    filtered_srcs = [f for f in ctx.files.srcs if f.basename in ctx.attr.outs]
    return [DefaultInfo(files = depset(filtered_srcs))]

_filter_vectors = rule(
    implementation = _filter_vectors_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = True),
        "outs": attr.string_list(),
    },
)

def wycheproof_vectors(name, srcs, outs, **kwargs):
    """Wraps genrule and filters srcs based on outs.

    Args:
        name: A unique name for this target.
        srcs: The full vector files available to copy.
        outs: The specific vector files to copy.
        **kwargs: Arguments passed through to the genrule.
    """

    _filter_vectors(
        name = name + "_filtered_srcs",
        srcs = srcs,
        outs = outs,
    )

    native.genrule(
        name = name,
        srcs = [":" + name + "_filtered_srcs"],
        outs = outs,
        cmd = "cp $(SRCS) $(@D)/",
        **kwargs
    )
