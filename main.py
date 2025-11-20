"""Entry point for the CI/CD digital twin skeleton project."""
import argparse


def main() -> None:
    """Initialize the CLI for the digital twin skeleton project."""
    parser = argparse.ArgumentParser(description="CI/CD Digital Twin Skeleton")
    parser.add_argument("--workflow", required=True, help="Path to GitHub Actions workflow file")
    parser.add_argument(
        "--output-dir",
        default="./output",
        help="Directory to store generated outputs",
    )
    args = parser.parse_args()

    print("Digital Twin skeleton initialized.")
    print(args)


if __name__ == "__main__":
    main()
