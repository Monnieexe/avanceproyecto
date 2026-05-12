import boto3
import warnings

# Ocultar las advertencias de versión de Python para que la consola se vea limpia
warnings.filterwarnings('ignore', category=DeprecationWarning)

REGION = 'us-east-1'

def reporte_ec2():
    print("--- REPORTE DE INSTANCIAS EC2 ---")
    ec2 = boto3.client('ec2', region_name=REGION)
    try:
        respuesta = ec2.describe_instances()
        if not respuesta['Reservations']:
            print("No hay instancias EC2 creadas actualmente.")
        for reserva in respuesta['Reservations']:
            for instancia in reserva['Instances']:
                estado = instancia['State']['Name']
                id_instancia = instancia['InstanceId']
                tipo = instancia['InstanceType']
                print(f"ID: {id_instancia} | Tipo: {tipo} | Estado: {estado}")
    except Exception as e:
        print("Error al listar EC2:", e)

def listar_s3():
    print("\n--- BUCKETS S3 DISPONIBLES ---")
    s3 = boto3.client('s3', region_name=REGION)
    try:
        respuesta = s3.list_buckets()
        if not respuesta['Buckets']:
            print("No hay buckets de S3 creados actualmente.")
        for bucket in respuesta['Buckets']:
            print(f"- {bucket['Name']}")
    except Exception as e:
        print("Error al listar S3:", e)

if __name__ == "__main__":
    print("Iniciando auditoría de recursos en AWS...\n")
    reporte_ec2()
    listar_s3()
    print("\nReporte finalizado.")