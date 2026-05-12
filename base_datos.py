import boto3
import time

REGION = 'us-east-1'

def crear_e_insertar():
    dynamodb = boto3.resource('dynamodb', region_name=REGION)
    
    # 1. Crear la tabla
    print("Creando tabla 'TransaccionesFinancieras'...")
    try:
        tabla = dynamodb.create_table(
            TableName='TransaccionesFinancieras',
            KeySchema=[{'AttributeName': 'TransaccionID', 'KeyType': 'HASH'}],
            AttributeDefinitions=[{'AttributeName': 'TransaccionID', 'AttributeType': 'S'}],
            BillingMode='PAY_PER_REQUEST'
        )
        
        # Esperar a que la tabla exista (tarda unos segundos en AWS)
        tabla.meta.client.get_waiter('table_exists').wait(TableName='TransaccionesFinancieras')
        print("¡Tabla creada con éxito!")
    except Exception as e:
        print("La tabla posiblemente ya existe o hubo un error:", e)
        tabla = dynamodb.Table('TransaccionesFinancieras')

    # 2. Insertar un registro de prueba
    print("Insertando un registro de prueba...")
    tabla.put_item(
        Item={
            'TransaccionID': 'TXT-001',
            'Monto': 1500,
            'Estado': 'Completado',
            'Cliente': 'Ivonne Fajardo'
        }
    )
    print("¡Registro insertado correctamente!")

if __name__ == "__main__":
    crear_e_insertar()