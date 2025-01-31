
## About

Third party plugins tools for python based applications.

## Setup

1. **Clone the repository**:
    ```sh
    git clone <repository-url>
    cd <repository-directory>
    ```

2. **Create and activate a virtual environment**:
    ```sh
    python -m venv venv
    source venv/bin/activate  # On Windows use `venv\Scripts\activate`
    ```

3. **Install dependencies**:
    ```sh
    pip install -r requirements.txt
    ```

4. **Set environment variables**:
    ```sh
    export SECRET_KEY="your_secret_key"
    ```

5. **Run the application**:
    ```sh
    flask run
    ```

## Usage

- **Dashboard**: Access the dashboard at `http://localhost:5000/`.
- **Run Package Scan**: Click on "Run Scan" under "Package Scan".
- **View Reports**: Click on "View Reports" to see the scan reports.

## Endpoints

- `/logs`: Streams real-time logs.
- `/scan/packages`: Initiates a package scan.
- `/scan/status`: Displays the scan status.
- `/download/<filename>`: Downloads the specified report file.
- `/scan/report`: Displays the scan report.
- `/`: Dashboard.
- `/login`: Login page.
- `/logout`: Logout.


## License

Free to use

## NOTE
i use gpt to develop code.
