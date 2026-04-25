#!/bin/bash

echo "╔═══════════════════════════════════════════════════════╗"
echo "║   VERIFICAÇÃO COMPLETA - Assignment 2                 ║"
echo "║   CA + PostgreSQL + Certificados                      ║"
echo "╚═══════════════════════════════════════════════════════╝"
echo ""

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[SECÇÃO 1/5] VERIFICAR CERTIFICADOS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ -f "ca/certs/ca.crt" ]; then
    echo -e "${GREEN}✓${NC} CA root certificate existe"
    if openssl x509 -noout -text -in ca/certs/ca.crt | grep -q "CA:TRUE"; then
        echo -e "${GREEN}✓${NC} CA:TRUE verificado"
    else
        echo -e "${RED}✗${NC} CA:TRUE NÃO encontrado!"
        ERRORS=$((ERRORS + 1))
    fi
else
    echo -e "${RED}✗${NC} CA root certificate NÃO existe!"
    ERRORS=$((ERRORS + 1))
fi

echo ""

CERTS=("postgres-server" "postgres-webapp" "postgres-readonly" "webserver" "vpn-server" "vpn-client" "radius-server" "radius-client" "ocsp")

for cert in "${CERTS[@]}"; do
    if [ -f "ca/certs/${cert}.crt" ]; then
        if openssl verify -CAfile ca/certs/ca.crt ca/certs/${cert}.crt &>/dev/null; then
            echo -e "${GREEN}✓${NC} ${cert}.crt - Válido"
        else
            echo -e "${RED}✗${NC} ${cert}.crt - Verificação FALHOU!"
            ERRORS=$((ERRORS + 1))
        fi
    else
        echo -e "${YELLOW}⚠${NC} ${cert}.crt - NÃO encontrado"
    fi
done

echo ""
if [ -f "ca/certs/dh2048.pem" ]; then
    echo -e "${GREEN}✓${NC} DH Parameters existem"
else
    echo -e "${YELLOW}⚠${NC} DH Parameters NÃO encontrados"
fi

if [ -f "ca/crl/ca.crl" ]; then
    echo -e "${GREEN}✓${NC} CRL existe"
else
    echo -e "${YELLOW}⚠${NC} CRL NÃO encontrada"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[SECÇÃO 2/5] VERIFICAR POSTGRESQL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if sudo systemctl is-active postgresql &>/dev/null; then
    echo -e "${GREEN}✓${NC} PostgreSQL está a correr"
else
    echo -e "${RED}✗${NC} PostgreSQL NÃO está a correr!"
    ERRORS=$((ERRORS + 1))
fi

SSL_STATUS=$(sudo -u postgres psql -d postgres -t -c "SHOW ssl;" 2>/dev/null | tr -d ' ')
if [ "$SSL_STATUS" = "on" ]; then
    echo -e "${GREEN}✓${NC} SSL está ativado"
else
    echo -e "${RED}✗${NC} SSL NÃO está ativado!"
    ERRORS=$((ERRORS + 1))
fi

echo ""
if sudo test -f /var/lib/postgresql/16/main/certs/postgres-server.crt; then
    echo -e "${GREEN}✓${NC} Certificado servidor copiado"
else
    echo -e "${RED}✗${NC} Certificado servidor NÃO copiado!"
    ERRORS=$((ERRORS + 1))
fi

if sudo test -f /var/lib/postgresql/16/main/certs/postgres-server.key; then
    echo -e "${GREEN}✓${NC} Chave privada servidor copiada"
else
    echo -e "${RED}✗${NC} Chave privada servidor NÃO copiada!"
    ERRORS=$((ERRORS + 1))
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[SECÇÃO 3/5] VERIFICAR BASE DE DADOS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if sudo -u postgres psql -lqt 2>/dev/null | cut -d \| -f 1 | grep -qw assignment2_db; then
    echo -e "${GREEN}✓${NC} Base de dados 'assignment2_db' existe"
else
    echo -e "${YELLOW}⚠${NC} Base de dados 'assignment2_db' NÃO existe"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "RESUMO FINAL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ $ERRORS -eq 0 ]; then
    echo -e "${GREEN}✓ VERIFICAÇÃO COMPLETA!${NC}"
    echo "Podes avançar!"
else
    echo -e "${RED}✗ Encontrados $ERRORS erros${NC}"
    echo "Revê os erros acima"
fi
