defmodule C509.MixProject do
  use Mix.Project

  def project do
    [
      app: :c509,
      version: "0.1.0",
      elixir: "~> 1.16",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package()
    ]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger, :public_key, :crypto]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  defp deps do
    [
      {:cbor, "~> 1.0"},
      {:rustler, "0.32.1", runtime: false}
    ]
  end

  defp description do
    """
    A library for working with C509 certificates
    """
  end

  defp package do
    [
      licenses: ["MIT"],
      links: %{
        "GitHub" => "https://github.com/mikekelly/c509-elixir"
      },
      files: ~w(lib priv native .formatter.exs mix.exs README.md .gitignore)
    ]
  end
end
