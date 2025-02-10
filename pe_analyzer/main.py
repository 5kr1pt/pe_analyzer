#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
from pe_analyzer import analyzer

def parse_arguments():
    """
    Trata os argumentos de linha de comando.
    """
    parser = argparse.ArgumentParser(
        description='Análise estática de arquivos executáveis Windows (PE Files) usando pefile.'
    )
    parser.add_argument(
        '--file', '-f',
        required=True,
        help='Caminho para o arquivo PE a ser analisado.'
    )
    return parser.parse_args()

def main():
    # Processa os argumentos
    args = parse_arguments()

    if not os.path.isfile(args.file):
        print(f"Erro: O arquivo '{args.file}' não existe.")
        sys.exit(1)

    # Realiza a análise e obtém o relatório
    report = analyzer.analyze_file(args.file)
    print("\n".join(report))

if __name__ == "__main__":
    main()
