# VeraDemo - Blab-a-Gag (Django-Python)

### Notice
**

This project is intentionally vulnerable! It contains known vulnerabilities and security errors in its code and is meant as an example project for software security scanning tools such as Veracode. Please do not report vulnerabilities in this project; the odds are they’re there on purpose :) .

## About

Blab-a-Gag is a simple forum type application that allows:

- Users can post a one-liner joke.
- Users can follow the jokes of other users or not (listen or ignore).
- Users can comment on other users messages (heckle).

### URLs

- `/feed` shows the jokes/heckles that are relevant to the current user.
- `/blabbers` shows a list of all other users and allows the current user to listen or ignore.
- `/profile` allows the current user to modify their profile.
- `/login` allows you to log in to your account
- `/register` allows you to create a new user account
- `/tools` shows a tools page that shows a fortune or lets you ping a host.
- `/reset` allows the user to reset the database

## Run Docker image (Easiest Method)

If you don't already have Docker this is a prerequisite.

### Download Docker

Visit [docker desktop](https://www.docker.com/products/docker-desktop/) and download the compatible version for your operating system. Follow the installation instructions and open the Docker app.

### Build your Docker image

Follow the instructions below for cloning and building the application through docker:

	git clone https://github.com/veracode-demo-labs/verademo-python.git
 	cd verademo-python
	docker build -t verademo-python .
	docker run --rm -p 8000:8000 --name verademo-python verademo-python
	
Navigate to: [http://127.0.0.1:8000](http://127.0.0.1:8000).

Then register as a new user and add some feeds!

## Run locally without Docker (Linux/Mac)

To run the program locally without Docker:

Prerequisite: Python 3.12.3

To check Python version: `python --version` or `python3 --version`

If you don't have Python, download it [here](https://www.python.org/downloads/)

To upgrade Python version, read [this guide](https://phoenixnap.com/kb/upgrade-python)
- NOTE: downloading via Python installer is recommended.

If your Python version is newer than the prerequisite, it is easier to use a [Python virtual environment](https://docs.python.org/3/library/venv.html) to run the project (this is already included in the dependency install below).

Clone the repository in terminal:

    git clone https://github.com/veracode-demo-labs/verademo-python.git
    cd verademo-python
Download dependencies and start the server:

    python -m venv env
    source env/bin/activate
    pip install -r requirements.txt
    python manage.py runserver
Navigate to: [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Run locally without Docker (Windows)

To run the program locally without Docker:

Prerequisite: Python 3.12.3

To check your Python version: `python --version` or `python3 --version`

If you don't have Python, download it [here](https://www.python.org/downloads/)

To upgrade your Python version read [this guide](https://phoenixnap.com/kb/upgrade-python)
- NOTE: Downloading via the Python installer is recommended.

If your Python version is newer than the prerequisite, it is easier to use a [Python virtual environment](https://docs.python.org/3/library/venv.html) to run the project (this is already included in the dependency install below).

Open Windows PowerShell and clone the repository:

    git clone https://github.com/veracode-demo-labs/verademo-python.git
    cd verademo-python
Download dependencies and start the server! (Try running console commands with `python3` if `python` isn't found)

    python -m venv env
    env\Scripts\activate
    pip install -r requirements.txt
    python manage.py runserver
Navigate to: [http://127.0.0.1:8000](http://127.0.0.1:8000).

## Exploitation Demos

See the [DEMO_NOTES](DEMO_NOTES.md) file for information on using this application with the various Veracode scan types.

Also see the `docs` folder for in-depth explanations of the various exploits exposed in this application.


## Technologies Used

- Django (Version 4.2.13)
- sqlite3 (Supported by Django)
