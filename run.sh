#!/usr/bin/env bash
# ShieldEye NeuralScan - Launch Script (SurfaceScan-style)

set -Eeuo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Icons (same as SurfaceScan, only those actually used)
ICON_INFO="ℹ️"
ICON_SUCCESS="✅"
ICON_WARNING="⚠️"
ICON_ERROR="❌"
ICON_ROCKET="🚀"
ICON_DB="🗄️"
ICON_EXIT="👋"

PROJECT_NAME="ShieldEye NeuralScan"
PYTHON_MIN="3.10"

# Script directory (resolve symlinks, so ./run.sh always works)
SOURCE="${BASH_SOURCE[0]}"
while [ -h "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"

print_info() {
    echo -e "${BLUE}${ICON_INFO} [INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}${ICON_SUCCESS} [SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}${ICON_WARNING} [WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}${ICON_ERROR} [ERROR]${NC} $1"
}

print_banner() {
    cat <<'EOF'



  .--.--.     ,---,                         ,--,                  ,---,.                     
 /  /    '. ,--.' |      ,--,             ,--.'|         ,---,  ,'  .' |                     
|  :  /`. / |  |  :    ,--.'|             |  | :       ,---.'|,---.'   |                     
;  |  |--`  :  :  :    |  |,              :  : '       |   | :|   |   .'                     
|  :  ;_    :  |  |,--.`--'_       ,---.  |  ' |       |   | |:   :  |-,      .--,   ,---.   
 \  \    `. |  :  '   |,' ,'|     /     \ '  | |     ,--.__| |:   |  ;/|    /_ ./|  /     \  
  `----.   \|  |   /' :'  | |    /    /  ||  | :    /   ,'   ||   :   .' , ' , ' : /    /  | 
  __ \  \  |'  :  | | ||  | :   .    ' / |'  : |__ .   '  /  ||   |  |-,/___/ \: |.    ' / | 
 /  /`--'  /|  |  ' | :'  : |__ '   ;   /||  | '.'|'   ; |:  |'   :  ;/| .  \  ' |'   ;   /| 
'--'.     / |  :  :_:,'|  | '.'|'   |  / |;  :    ;|   | '/  '|   |    \  \  ;   :'   |  / | 
  `--'---'  |  | ,'    ;  :    ;|   :    ||  ,   / |   :    :||   :   .'   \  \  ;|   :    | 
            `--''      |  ,   /  \   \  /  ---`-'   \   \  /  |   | ,'      :  \  \\   \  /  
                        ---`-'    `----'             `----'   `----'         \  ' ; `----'   
                                                                              `--`           



 ShieldEye NeuralScan Launcher
--------------------------------
EOF
}

require_command() {
    local cmd="$1"
    local name="${2:-$1}"
    if ! command -v "$cmd" &> /dev/null; then
        print_error "$name is not installed"
        return 1
    fi
    return 0
}

check_dependencies() {
    print_info "Checking system dependencies..."

    require_command python3 "Python 3" || exit 1
    require_command pkg-config "pkg-config" || exit 1

    # Check Python version
    local py_ver
    py_ver=$(python3 --version 2>&1 | awk '{print $2}')
    if ! python3 -c "import sys; exit(0 if sys.version_info >= (3, 10) else 1)" 2>/dev/null; then
        print_error "Python ${PYTHON_MIN}+ is required. Found: ${py_ver}"
        exit 1
    fi

    # Check GTK4 + PyGObject
    if ! pkg-config --exists gtk4; then
        print_error "GTK4 development libraries not found"
        print_info "Install with: sudo apt install libgtk-4-dev gobject-introspection libgirepository1.0-dev (Ubuntu/Debian)"
        exit 1
    fi

    if ! python3 -c "import gi; gi.require_version('Gtk', '4.0'); from gi.repository import Gtk" 2>/dev/null; then
        print_error "PyGObject for GTK4 not found"
        print_info "Install with: sudo apt install python3-gi (Ubuntu/Debian) lub odpowiednik dla Twojej dystrybucji"
        exit 1
    fi

    print_success "All core dependencies satisfied"
}

setup_environment() {
    print_info "Setting up environment..."

    export GTK_THEME="${GTK_THEME:-Adwaita:dark}"

    mkdir -p "${PROJECT_ROOT}/data" "${PROJECT_ROOT}/logs"

    # Python path (project root)
    export PYTHONPATH="${PROJECT_ROOT}:${PYTHONPATH:-}"

    print_success "Environment configured"
}

install_python_deps() {
    print_info "Installing Python dependencies (virtualenv)..."

    cd "${PROJECT_ROOT}"

    if [ ! -d ".venv" ]; then
        print_info "Creating virtual environment (.venv)..."
        python3 -m venv .venv
    fi

    # shellcheck source=/dev/null
    source .venv/bin/activate

    pip install --upgrade pip setuptools wheel

    if [ -f "requirements.txt" ]; then
        print_info "Installing requirements.txt..."
        pip install -r requirements.txt
    fi

    print_success "Python dependencies installed"
}

install_requirements() {
    print_info "Checking system deps and installing Python packages..."
    check_dependencies
    install_python_deps

    # Copy default config if missing
    if [ ! -f "${PROJECT_ROOT}/data/config.json" ] && [ -f "${PROJECT_ROOT}/config.default.json" ]; then
        cp "${PROJECT_ROOT}/config.default.json" "${PROJECT_ROOT}/data/config.json"
        print_info "Created default configuration (data/config.json)"
    fi

    print_success "Requirements installation finished"
}

run_gui() {
    print_info "Launching ${PROJECT_NAME} (GTK4 GUI)..."

    cd "${PROJECT_ROOT}"

    if [ ! -d ".venv" ]; then
        print_warning "Virtualenv .venv not found. Installing requirements first..."
        install_requirements
    fi

    # shellcheck source=/dev/null
    source .venv/bin/activate

    setup_environment

    # Run GTK application via module to avoid needing a top-level run.py
    if DBUS_SESSION_BUS_ADDRESS= python3 -m gui.main; then
        print_success "Application exited normally"
    else
        local exit_code=$?
        print_error "Application exited with code ${exit_code}"
        case ${exit_code} in
            1)
                print_info "Check logs in ./logs or console output for details"
                ;;
            130)
                print_info "Application was interrupted by user (Ctrl+C)"
                ;;
            *)
                print_info "Unexpected exit code: ${exit_code}"
                ;;
        esac
        exit ${exit_code}
    fi
}

run_tests() {
    print_info "Running tests..."

    cd "${PROJECT_ROOT}"

    if [ ! -d ".venv" ]; then
        print_warning "Virtualenv .venv not found. Installing requirements first..."
        install_requirements
    fi

    # shellcheck source=/dev/null
    source .venv/bin/activate
    if command -v pytest &> /dev/null; then
        pytest tests/ -v || true
    else
        print_warning "pytest not installed; uncomment dev tools in requirements.txt to run tests"
    fi

    print_success "Test run finished"
}

show_help() {
    echo "${PROJECT_NAME} - Launch Script"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --help, -h          Show this help message"
    echo "  --mode MODE         Non-interactive mode: gui|install|test|exit (or 1-4)"
    echo "  --no-banner         Disable ASCII banner"
    echo ""
    echo "Examples:"
    echo "  ./run.sh                # Interactive menu"
    echo "  ./run.sh --mode gui     # Directly launch GUI"
    echo "  ./run.sh --mode install # Check deps + install requirements"
}

main() {
    if [[ "${NEURALSCAN_NO_BANNER:-false}" != "true" ]]; then
        print_banner
    fi

    local mode="${NEURALSCAN_MODE:-}"

    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --mode)
                if [[ $# -lt 2 ]]; then
                    print_error "--mode requires an argument"
                    show_help
                    exit 1
                fi
                mode="$2"
                shift 2
                ;;
            --no-banner)
                export NEURALSCAN_NO_BANNER="true"
                shift
                ;;
            *)
                print_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done

    if [[ -n "${mode}" ]]; then
        case "${mode}" in
            1|gui)
                run_gui
                ;;
            2|install)
                install_requirements
                ;;
            3|test)
                run_tests
                ;;
            4|exit)
                echo "Goodbye."
                exit 0
                ;;
            *)
                print_error "Unknown mode: ${mode}"
                show_help
                exit 1
                ;;
        esac
        exit 0
    fi

    echo ""
    echo "Choose action:"
    echo "  1) ${ICON_ROCKET} Run ${PROJECT_NAME}"
    echo "  2) ${ICON_INFO} Install requirements (check deps + Python packages)"
    echo "  3) ${ICON_DB} Run tests"
    echo "  4) ${ICON_EXIT} Exit"
    echo ""
    read -rp "Enter choice [1-4]: " choice

    case "${choice}" in
        1)
            run_gui
            ;;
        2)
            install_requirements
            ;;
        3)
            run_tests
            ;;
        4)
            echo "Goodbye."
            exit 0
            ;;
        *)
            print_error "Invalid choice. Please run the script again and choose 1-4."
            exit 1
            ;;
    esac
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}Interrupted by user${NC}"; exit 130' INT

# Run main function
main "$@"
