FROM python:3.9-slim


# Install Tkinter and other necessary packages
RUN apt-get update && apt-get install -y \
    python3-tk \
    tk-dev
    
# Set the working directory in the container
WORKDIR /app

COPY requirements.txt /app

# Install Django
RUN pip install -r requirements.txt

# Copy the current directory contents into the container at /app
COPY . /app/

# Expose a port (e.g., 8000) that your application will run on
EXPOSE 8019


