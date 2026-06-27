"""Docker/Trivy integration kept separate so scanner.py has no direct Docker dependency."""
import json
import logging
from pathlib import Path
from typing import Optional, Any


class TrivyScanner:
    def __init__(self):
        self.docker_client = None
        self.trivy_available = False

    def _ensure_trivy_ready(self) -> Optional[str]:
        if self.trivy_available:
            return None

        self.docker_client = self._initialize_docker_client()
        if not self.docker_client:
            self.trivy_available = False
            return "Trivy scan is unavailable because Docker is not running or not accessible."

        pull_ok = self._pull_trivy_image()
        self.trivy_available = bool(pull_ok)
        if not pull_ok:
            return "Trivy scan is unavailable because the Trivy Docker image could not be prepared."
        return None

    def _initialize_docker_client(self) -> Optional[Any]:
        try:
            import docker
            from docker.errors import DockerException
        except ImportError as e:
            logging.info(f"Docker SDK not installed: {e}. Trivy scan will be unavailable.")
            return None
        except Exception as e:
            logging.warning(f"Unexpected error importing Docker SDK: {e}")
            return None

        try:
            client = docker.from_env()
            client.ping()
            logging.info("Docker connection established.")
            return client
        except DockerException as e:
            logging.warning(f"Docker error: {e}. Docker is not running or not accessible. Trivy scan will be unavailable.")
            return None
        except Exception as e:
            logging.error(f"Unexpected error connecting to Docker: {e}")
            return None

    def _pull_trivy_image(self) -> bool:
        if not self.docker_client:
            return False
        try:
            import docker
            from docker.errors import ImageNotFound, APIError

            self.docker_client.images.get("aquasec/trivy:latest")
            logging.info("Trivy image already exists.")
            return True
        except ImageNotFound:
            try:
                logging.info("Pulling Trivy image, this may take a moment...")
                self.docker_client.images.pull("aquasec/trivy", "latest")
                logging.info("Trivy image pulled successfully.")
                return True
            except APIError as e:
                logging.error(f"Docker API error while pulling Trivy image: {e}")
                return False
            except Exception as e:
                logging.error(f"Failed to pull Trivy image: {e}")
                return False
        except APIError as e:
            logging.error(f"Docker API error checking for Trivy image: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error checking Trivy image: {e}")
            return False

    def _scan_with_trivy(self, file_path: str) -> str:
        if not self.docker_client:
            return "Trivy scan is unavailable because Docker is not running."
        try:
            import docker
            from docker.errors import ContainerError, ImageNotFound, APIError

            command = [
                'fs',
                '--scanners', 'vuln,secret',
                '--format', 'json',
                '--quiet',
                '--no-progress',
                f'/scan/{Path(file_path).name}'
            ]

            container = self.docker_client.containers.run(
                'aquasec/trivy:latest',
                command,
                volumes={str(Path(file_path).resolve().parent): {'bind': '/scan', 'mode': 'ro'}},
                remove=True,
                stderr=True,
                stdout=True
            )

            output = container.decode('utf-8')
            return self._parse_trivy_json(output)
        except ImageNotFound as e:
            logging.error(f"Trivy image not found: {e}")
            return "Trivy scan failed: Trivy Docker image not found. Run installation to pull the image."
        except ContainerError as e:
            logging.error(f"Trivy container error: {e}")
            return f"Trivy scan failed: Container execution error - {e}"
        except APIError as e:
            logging.error(f"Docker API error during Trivy scan: {e}")
            return f"Trivy scan failed: Docker API error - {e}"
        except Exception as e:
            error_msg = getattr(e, 'stderr', b'').decode('utf-8') if hasattr(e, 'stderr') and e.stderr else str(e)
            logging.error(f"Unexpected error during Trivy scan: {error_msg}")
            return f"Trivy scan failed: {error_msg}"

    def _parse_trivy_json(self, json_string: str) -> str:
        try:
            data = json.loads(json_string)
        except json.JSONDecodeError:
            return "Could not parse Trivy output. It might not be valid JSON."

        if not data or 'Results' not in data or not data['Results']:
            return "No vulnerabilities or secrets found by Trivy."

        summary = []
        for result in data['Results']:
            target = result.get('Target', 'Unknown Target')
            summary.append(f"Target: {target}")

            if 'Vulnerabilities' in result and result['Vulnerabilities']:
                summary.append("  Vulnerabilities:")
                for vuln in result['Vulnerabilities']:
                    line = f"    - {vuln['VulnerabilityID']} ({vuln['Severity']}): {vuln['Title']}"
                    summary.append(line)

            if 'Secrets' in result and result['Secrets']:
                summary.append("  Secrets Found:")
                for secret in result['Secrets']:
                    line = f"    - {secret['Title']} (Severity: {secret['Severity']}) at line {secret['StartLine']}"
                    summary.append(line)

        return "\n".join(summary) if summary else "No issues found by Trivy."
