import sys
import docker
import subprocess
import yaml

def extract_numeric_ports(exposed_ports):
    numeric_ports = []
    for port in exposed_ports:
        numeric_port = ''.join(filter(str.isdigit, port))
        numeric_ports.append(numeric_port)
    return numeric_ports

def generate_docker_compose(image_name, numeric_ports):
    docker_compose_content = {
        'version': '3',
        'services': {
            'app': {
                'image': image_name,
                'ports': [f"{port}:{port}" for port in numeric_ports],
                'environment': {
                    'DEBUG': '1'
                }
            }
        }
    }

    return yaml.dump(docker_compose_content, default_flow_style=False)

def inspect_docker_image(image_name):
    client = docker.from_env()

    try:
        image = client.images.get(image_name)
    except docker.errors.ImageNotFound:
        print(f"Image '{image_name}' not found on your system. Pulling the image...")
        try:
            client.images.pull(image_name)
            print(f"Image '{image_name}' successfully pulled.")
        except docker.errors.APIError as e:
            print(f"Error pulling image '{image_name}': {e}")
            sys.exit(1)
        image = client.images.get(image_name)

    ports = image.attrs['Config']['ExposedPorts']
    numeric_ports = extract_numeric_ports(ports)
    return numeric_ports

def execute_docker_compose(compose_path='docker-compose.yml'):
    try:
        subprocess.run(['docker-compose', '-f', compose_path, 'up', '-d'], check=True)
        print(f"Docker Compose executed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing Docker Compose: {e}")
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python inspect_docker_image.py <image_name>")
        sys.exit(1)

    image_name = sys.argv[1]
    numeric_ports = inspect_docker_image(image_name)

    docker_compose_content = generate_docker_compose(image_name, numeric_ports)

    with open('docker-compose.yml', 'w') as compose_file:
        compose_file.write(docker_compose_content)

    print(f"docker-compose.yml file generated successfully for '{image_name}'.")

    execute_docker_compose()

