defmodule CapstoneEx do
  @moduledoc """
  An Elixir wrapper for the Capstone Disassembly Framework using Rustler.
  """

  # This module will hold the NIF functions. The name must match the one
  # in the `rustler::init!` macro in our lib.rs file.
  defmodule Native do
    use Rustler, otp_app: :capstone_ex, crate: "excap"

    # This is a fallback for when the NIF is not loaded.
    def disassemble(_code, _arch, _mode), do: :erlang.nif_error(:nif_not_loaded)
  end

  @doc """
  Disassembles a binary string of machine code.

  ## Parameters
    - `code`: A binary string containing the machine code.
    - `arch`: The architecture atom. Supported: `:x86`, `:arm`, `:arm64`.
    - `mode`: The mode atom. Supported: `:mode16`, `:mode32`, `:mode64`, `:mode_arm`, `:mode_thumb`.

  ## Returns
    - `{:ok, list_of_instructions}` on success.
    - `{:error, reason}` on failure.

  Each instruction in the list is a map containing `:address`, `:mnemonic`,
  `:op_str`, and `:bytes`.

  ## Examples

      iex> code = <<0x55, 0x48, 0x89, 0xe5, 0xc3>> # push rbp; mov rsp, rbp; ret
      iex> CapstoneEx.disassemble(code, :x86, :mode64)
      {:ok, [
        %{address: 4096, bytes: <<85>>, mnemonic: "push", op_str: "rbp"},
        %{address: 4097, bytes: <<72, 137, 229>>, mnemonic: "mov", op_str: "rbp, rsp"},
        %{address: 4100, bytes: <<195>>, mnemonic: "ret", op_str: ""}
      ]}

      iex> CapstoneEx.disassemble(<<0x00, 0x00, 0x00, 0x00>>, :unsupported, :mode64)
      {:error, "unsupported_architecture"}
  """
  def disassemble(code, arch, mode) when is_binary(code) and is_atom(arch) and is_atom(mode) do
    Native.disassemble(code, arch, mode)
  end
end
