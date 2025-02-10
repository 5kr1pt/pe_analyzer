# PE Analyzer v1.0 👾

Projeto para análise estática de arquivos executáveis do Windows (PE Files) utilizando a biblioteca **pefile**.

## Funcionalidades

- Extração de informações dos headers, seções, importações e recursos.
- Identificação de anomalias, como:
  - Headers inválidos.
  - Seções com nomes ou tamanhos atípicos.
  - Importações incomuns.
  - Ausência de assinatura digital.
- Geração de relatório final com pontos de atenção.

## Estrutura do Projeto

```bash
pe_analyzer/
├── README.md
├── requirements.txt
├── setup.py
└── pe_analyzer/
    ├── __init__.py
    ├── analyzer.py
    └── main.py
```

## Instalação

1. Clone o repositório:

   ´git clone https://github.com/ScriptHit/pe_analyzer.git´
   ´cd pe_analyzer´

2. Crie um ambiente virtual (opcional, mas recomendado):


´python -m venv venv´
source venv/bin/activate   # Linux/Mac
venv\Scripts\activate      # Windows


3. Instale as dependências:
´pip install -r requirements.txt´

## Uso
Para executar a análise em um arquivo PE, utilize:

´python -m pe_analyzer.main --file "path/arquivo.exe"´


Para executar os testes unitários (exemplo):

´python -m unittest discover -s tests´
