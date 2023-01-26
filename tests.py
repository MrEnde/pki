import requests


url = 'https://dss-server-mrendor.cloud.okteto.net'
# url = 'http://localhost:8001'

request_upload = requests.post(
    url=f"{url}/dss/v1/upload/",
    files=[("file", open("contract_3.docx", "rb")), ],
    headers={'content_type': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'}
)

document_id = request_upload.json()["document_id"]


params = {
    'signatures_specs': [
        {'name': 'Представитель школы-владельца', 'box': [220, 560, 60, 460], 'credential_id': 'testing-ca/Школа №1788'},
        {'name': 'Школа-владелец', 'box': [440, 560, 310, 460], 'credential_id': 'testing-ca/Школа №1788'},
        {'name': 'Представитель школы-получателя', 'box': [220, 500, 60, 400], 'credential_id': 'testing-ca/Школа №1788'},
        {'name': 'Школа-получатель', 'box': [440, 500, 310, 400], 'credential_id': 'testing-ca/Школа №1788'}
    ],
    'document_id': document_id
}
request_sign = requests.post(
    url=f"{url}/dss/v1/sign_docx/",
    json=params
)

print(request_sign)

with open("signed_file.pdf", "wb") as file:
    file.write(request_sign.content)

# EquipContractTemplate
# Представитель школы-владельца [240, 560, 80, 460]
# Школа-владелец [210, 500, 80, 400]
# Представитель школы-получателя [490, 560, 330, 460]
# Школа-получатель [460, 500, 330, 400]

# ContractTemplate
# Представитель школы-владельца [240, 440, 80, 340]
# Школа-владелец [490, 440, 330, 340]
# Представитель школы-получателя [240, 320, 80, 220]
# Школа-получатель [490, 320, 330, 220]

# RoomContractTemplate
# Представитель школы-владельца [220, 560, 60, 460]
# Школа-владелец [440, 560, 310, 460]
# Представитель школы-получателя [220, 500, 60, 400]
# Школа-получатель [440, 500, 310, 400]
