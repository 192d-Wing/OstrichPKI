#!/bin/bash
#
# OstrichPKI Development Environment Manager
#
# COMPLIANCE MAPPING:
# - NIST 800-53: CM-2 (Baseline Configuration)
#
# Usage:
#   ./scripts/dev-env.sh start     # Start all services
#   ./scripts/dev-env.sh stop      # Stop all services
#   ./scripts/dev-env.sh restart   # Restart all services
#   ./scripts/dev-env.sh logs      # View logs
#   ./scripts/dev-env.sh status    # Check service status
#   ./scripts/dev-env.sh clean     # Remove all containers and volumes
#   ./scripts/dev-env.sh build     # Rebuild containers
#
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
COMPOSE_FILE="$PROJECT_ROOT/docker-compose.dev.yml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

check_docker() {
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed. Please install Docker first."
        exit 1
    fi
    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running. Please start Docker first."
        exit 1
    fi
}

start_services() {
    log_info "Starting OstrichPKI development environment..."

    docker compose -f "$COMPOSE_FILE" up -d "$@"

    log_info "Waiting for services to be healthy..."

    # Wait for Keycloak to be ready (it takes the longest)
    local max_attempts=60
    local attempt=0
    while [ $attempt -lt $max_attempts ]; do
        if docker compose -f "$COMPOSE_FILE" exec -T keycloak curl -sf http://localhost:8080/health/ready > /dev/null 2>&1; then
            break
        fi
        attempt=$((attempt + 1))
        echo -n "."
        sleep 2
    done
    echo ""

    if [ $attempt -eq $max_attempts ]; then
        log_warn "Keycloak may still be starting. Check logs with: ./scripts/dev-env.sh logs keycloak"
    else
        log_success "All services are running!"
    fi

    echo ""
    echo "Access URLs:"
    echo "  Web UI:      http://localhost:3000"
    echo "  Keycloak:    http://localhost:8180 (admin/admin)"
    echo "  PostgreSQL:  localhost:5432 (ostrich/ostrich_dev_password)"
    echo ""
    echo "Test Users (in Keycloak):"
    echo "  admin/admin123        - Full administrator"
    echo "  caoperator/caoperator123 - CA operator"
    echo "  auditor/auditor123    - Auditor (read-only)"
    echo "  viewer/viewer123      - Viewer (read-only)"
    echo ""
    echo "Note: First login will require password change"
}

stop_services() {
    log_info "Stopping OstrichPKI development environment..."
    docker compose -f "$COMPOSE_FILE" down "$@"
    log_success "All services stopped."
}

restart_services() {
    log_info "Restarting OstrichPKI development environment..."
    docker compose -f "$COMPOSE_FILE" restart "$@"
    log_success "Services restarted."
}

show_logs() {
    docker compose -f "$COMPOSE_FILE" logs -f "$@"
}

show_status() {
    echo "Service Status:"
    echo "==============="
    docker compose -f "$COMPOSE_FILE" ps
    echo ""
    echo "Health Checks:"
    echo "=============="
    for service in postgres keycloak web-ui ca acme ocsp scms kra; do
        status=$(docker compose -f "$COMPOSE_FILE" ps --format json "$service" 2>/dev/null | grep -o '"Health":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
        if [ "$status" = "healthy" ]; then
            echo -e "  $service: ${GREEN}$status${NC}"
        elif [ "$status" = "starting" ]; then
            echo -e "  $service: ${YELLOW}$status${NC}"
        else
            echo -e "  $service: ${RED}$status${NC}"
        fi
    done
}

clean_all() {
    log_warn "This will remove all containers, volumes, and images for the development environment."
    read -p "Are you sure? (y/N) " -n 1 -r
    echo ""
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        log_info "Cleaning up development environment..."
        docker compose -f "$COMPOSE_FILE" down -v --rmi local
        log_success "Cleanup complete."
    else
        log_info "Cleanup cancelled."
    fi
}

build_services() {
    log_info "Building OstrichPKI services..."
    docker compose -f "$COMPOSE_FILE" build "$@"
    log_success "Build complete."
}

show_help() {
    echo "OstrichPKI Development Environment Manager"
    echo ""
    echo "Usage: $0 <command> [options]"
    echo ""
    echo "Commands:"
    echo "  start [service...]   Start all or specific services"
    echo "  stop [service...]    Stop all or specific services"
    echo "  restart [service...] Restart all or specific services"
    echo "  logs [service...]    View logs (follow mode)"
    echo "  status               Show service status"
    echo "  clean                Remove all containers, volumes, and images"
    echo "  build [service...]   Build or rebuild services"
    echo "  help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 start                # Start all services"
    echo "  $0 start web-ui keycloak # Start only web-ui and keycloak"
    echo "  $0 logs web-ui          # Follow web-ui logs"
    echo "  $0 build web-ui         # Rebuild web-ui container"
}

# Main
check_docker

case "${1:-}" in
    start)
        shift
        start_services "$@"
        ;;
    stop)
        shift
        stop_services "$@"
        ;;
    restart)
        shift
        restart_services "$@"
        ;;
    logs)
        shift
        show_logs "$@"
        ;;
    status)
        show_status
        ;;
    clean)
        clean_all
        ;;
    build)
        shift
        build_services "$@"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        log_error "Unknown command: ${1:-}"
        echo ""
        show_help
        exit 1
        ;;
esac
