# Standard Python libraries.
import asyncio
import json

# Third party Python libraries.
import aiohttp

# Custom Python libraries.
from insightvm import generate_headers, BASE_URL
from secrets import SECRETS


class DataFetcher:
    """DataFetcher utilizes aiohttp to make asynchronous requests to the API to pull large
    amounts of data at once.
    """
    def __init__(self, api_endpoint, total_pages):
        self.api_endpoint = api_endpoint  # API endoint to retrieve from.
        self.total_pages = total_pages  # Number of pages needed to retrieve.
        self.all_data = []  # Contains all the data retrieved.
        self.size = 500  # Max assets that can be pulled at once in InsightVM.
        self.aiohttp_max_connections = 20  # Number of simultaneous connections. aiohttp default is 100 which can crush the console.

    async def fetch(self, session, url):  # noqa
        """Retrieve data from url.
        """

        async with session.get(url) as response:
            return await response.read()


    async def run(self):  # noqa
        """Makes the asynchronous HTTP requests and bundles the data in all_data.
        """

        # Create aiohttp BasicAuth object.
        auth = aiohttp.BasicAuth(SECRETS['insightvm']['username'], SECRETS['insightvm']['password'])

        # Create empty tasks list.
        tasks = []

        # Create a connector instance in order to throttle the number of requests made to 10.
        # Want to avoid overwhelming the console.
        # https://aiohttp.readthedocs.io/en/stable/client_advanced.html#connectors
        connector = aiohttp.TCPConnector(limit=self.aiohttp_max_connections)

        # Fetch all responses within one Client session, keep connection alive for all requests.
        # https://aiohttp.readthedocs.io/en/stable/client_reference.html
        async with aiohttp.ClientSession(connector=connector, read_timeout=0, auth=auth, headers=generate_headers()) as session:

            for i in range(self.total_pages):
                # Construct entire URL.
                url = "{}{}?page={}&size={}".format(BASE_URL, self.api_endpoint, i, self.size)

                # print("Fetching data from: {}".format(url))
                task = asyncio.ensure_future(self.fetch(session, url))
                tasks.append(task)

            responses = await asyncio.gather(*tasks)

            # You now have all response bodies in the response variable.
            for response in responses:
                json_response = json.loads(response.decode('utf-8'))
                try:
                    for vuln in json_response['resources']:
                        self.all_data.append(vuln)

                except KeyError:
                    print(json_response)

        return self.all_data
