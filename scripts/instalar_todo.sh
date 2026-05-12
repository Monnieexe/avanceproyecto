#!/bin/bash
echo "Instalando paquetes esenciales..."
sudo yum update -y
sudo yum install git vim python3 -y

echo "Asegurando que Docker esté listo..."
sudo dnf install docker -y
sudo systemctl start docker
sudo usermod -a -G docker ec2-user

echo "Instalando dependencias de tu proyecto Node.js..."
npm install

echo "¡Entorno listo, Ivonne!"

