import pefile

def check_pe_header(pe, report):
    """
    Verifica anomalias nos headers do arquivo PE.
    """
    # Verifica o DOS Header: deve conter 'MZ' (0x5A4D)
    if pe.DOS_HEADER.e_magic != 0x5A4D:
        report.append("Anomalia: DOS Header inválido (não contém 'MZ').")
    else:
        report.append("DOS Header válido (contém 'MZ').")
    
    # Verifica a assinatura do PE: deve ser 'PE\\0\\0' (0x00004550)
    if pe.NT_HEADERS.Signature != 0x00004550:
        report.append("Anomalia: Assinatura PE inválida (não contém 'PE\\0\\0').")
    else:
        report.append("Assinatura PE válida (contém 'PE\\0\\0').")
    
    # Verifica o AddressOfEntryPoint
    if pe.OPTIONAL_HEADER.AddressOfEntryPoint == 0:
        report.append("Atenção: AddressOfEntryPoint é 0, pode indicar anomalia.")
    else:
        report.append("AddressOfEntryPoint válido.")

def check_sections(pe, report):
    """
    Verifica as seções do arquivo PE para identificar anomalias.
    """
    common_sections = ['.text', '.data', '.rdata', '.rsrc', '.reloc', '.pdata', '.bss']
    for section in pe.sections:
        # Converte o nome da seção removendo caracteres nulos
        section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
        report.append(f"Seção encontrada: {section_name}")
        
        # Seção com nome atípico
        if section_name not in common_sections:
            report.append(f"-> Alerta: Seção '{section_name}' possui nome atípico.")
        
        # Tamanho virtual zero
        if section.Misc_VirtualSize == 0:
            report.append(f"-> Alerta: Seção '{section_name}' possui tamanho virtual 0.")
        
        # Tamanho virtual muito alto (exemplo: > 10MB)
        if section.Misc_VirtualSize > 10 * 1024 * 1024:
            report.append(f"-> Alerta: Seção '{section_name}' possui tamanho virtual muito alto ({section.Misc_VirtualSize} bytes).")

def check_imports(pe, report):
    """
    Verifica as importações do arquivo PE para identificar anomalias.
    """
    common_dlls = [
        'kernel32.dll', 'user32.dll', 'gdi32.dll', 
        'advapi32.dll', 'ws2_32.dll', 'shell32.dll', 'ole32.dll'
    ]
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore').lower()
            report.append(f"DLL importada: {dll_name}")
            if dll_name not in common_dlls:
                report.append(f"-> Alerta: DLL '{dll_name}' não é comum e pode indicar comportamento suspeito.")
            for imp in entry.imports:
                func_name = imp.name.decode('utf-8', errors='ignore') if imp.name else f"Ordinal_{imp.ordinal}"
                report.append(f"   Função importada: {func_name}")
    else:
        report.append("Nenhuma importação encontrada.")

def check_resources(pe, report):
    """
    Verifica os recursos do arquivo PE.
    """
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        report.append("Recursos encontrados:")
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if resource_type.name:
                res_name = resource_type.name.decode('utf-8', errors='ignore')
            else:
                res_name = str(resource_type.struct.Id)
            report.append(f"-> Tipo de recurso: {res_name}")
    else:
        report.append("Nenhum recurso encontrado no arquivo.")

def check_digital_signature(pe, report):
    """
    Verifica se o arquivo possui assinatura digital.
    """
    if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY'):
        report.append("Assinatura digital encontrada.")
    else:
        report.append("Atenção: Assinatura digital ausente.")

def analyze_file(file_path):
    """
    Realiza a análise completa do arquivo PE.
    Retorna uma lista com o relatório dos pontos de atenção.
    """
    report = []
    report.append("=== Início da Análise do Arquivo PE ===")

    try:
        pe = pefile.PE(file_path)
    except pefile.PEFormatError as e:
        report.append(f"Erro ao processar o arquivo PE: {e}")
        return report

    report.append("\n--- Análise dos Headers ---")
    check_pe_header(pe, report)

    report.append("\n--- Análise das Seções ---")
    check_sections(pe, report)

    report.append("\n--- Análise das Importações ---")
    check_imports(pe, report)

    report.append("\n--- Análise dos Recursos ---")
    check_resources(pe, report)

    report.append("\n--- Verificação da Assinatura Digital ---")
    check_digital_signature(pe, report)

    report.append("\n=== Fim da Análise ===")
    return report
