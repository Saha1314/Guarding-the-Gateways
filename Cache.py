import requests
import time
import pickle

# Define the cache file name
CACHE_FILE = 'cache.pickle'

# Load the cache data from the file (if it exists)
try:
    with open(CACHE_FILE, 'rb') as cache_file:
        cache = pickle.load(cache_file)
except FileNotFoundError:
    cache = {}

def save_cache():
    # Save the cache data to the file
    with open(CACHE_FILE, 'wb') as cache_file:
        pickle.dump(cache, cache_file)

def cached_request(url):
    """
    Custom function to make a cached request.
    
    Args:
        url (str): The URL to request.
        
    Returns:
        requests.Response: The response object.
    """
    # If the URL is in the cache, return the cached response
    start_time = time.time()
    if url in cache:
        print("Using cached response for", url)
        a=cache[url]
        end_time = time.time() 
        print(f"Time taken for {url} from cache: {end_time - start_time} seconds")
        return a
    
    # If the URL is not in the cache, fetch the response from the server
    start_time = time.time()  # Record the start time
    response = requests.get(url)
    end_time = time.time()  # Record the end time
    
    # Cache the response for future use
    cache[url] = response
    save_cache()  # Save the updated cache to the file

    # Calculate and print the difference in response time
    print(f"Time taken for {url}: {end_time - start_time} seconds")
    
    return response

