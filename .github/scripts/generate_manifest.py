import os
import sys
import json
import urllib.request
import urllib.error
import yaml

def fetch_json(url, token=None):
    req = urllib.request.Request(url)
    if token:
        req.add_header('Authorization', f'Bearer {token}')
    req.add_header('Accept', 'application/vnd.github.v3+json')
    try:
        with urllib.request.urlopen(req) as response:
            return json.loads(response.read().decode())
    except urllib.error.URLError as e:
        print(f"Error fetching {url}: {e}")
        return None

def fetch_text(url):
    try:
        with urllib.request.urlopen(url) as response:
            return response.read().decode('utf-8')
    except urllib.error.URLError as e:
        print(f"Error fetching {url}: {e}")
        return None

def main():
    repo = os.environ.get('GITHUB_REPOSITORY')
    token = os.environ.get('GITHUB_TOKEN')
    
    if not repo:
        print("GITHUB_REPOSITORY environment variable is required")
        sys.exit(1)
        
    with open('build.yaml', 'r') as f:
        base_build_info = yaml.safe_load(f)

    manifest_entry = {
        "guid": base_build_info.get('guid'),
        "name": base_build_info.get('name'),
        "description": base_build_info.get('description', ''),
        "overview": base_build_info.get('overview', ''),
        "owner": base_build_info.get('owner', ''),
        "category": base_build_info.get('category', ''),
        "imageUrl": base_build_info.get('imageUrl', ''),
        "versions": []
    }

    releases_url = f"https://api.github.com/repos/{repo}/releases?per_page=100"
    releases = fetch_json(releases_url, token)
    
    if not isinstance(releases, list):
        print(f"Failed to fetch releases (or none found): {releases}")
        releases = []

    for release in releases:
        if release.get('draft') or release.get('prerelease'):
            continue
            
        tag_name = release.get('tag_name')
        
        # Try to read the build.yaml from the specific tag using git locally
        import subprocess
        tag_build_yaml_text = None
        try:
            tag_build_yaml_text = subprocess.check_output(
                ['git', 'show', f'{tag_name}:build.yaml'], 
                stderr=subprocess.DEVNULL
            ).decode('utf-8')
        except subprocess.CalledProcessError:
            pass

        if tag_build_yaml_text:
            try:
                tag_build_info = yaml.safe_load(tag_build_yaml_text)
            except Exception:
                tag_build_info = base_build_info
        else:
            tag_build_info = base_build_info
            
        if not isinstance(tag_build_info, dict):
            tag_build_info = base_build_info
            
        version_str = tag_build_info.get('version', tag_name.lstrip('v'))
        target_abi = tag_build_info.get('targetAbi', '10.11.0.0')

        assets = release.get('assets', [])
        zip_asset = next((a for a in assets if a['name'].endswith('.zip')), None)
        
        if not zip_asset:
            print(f"Skipping release {tag_name}: No zip asset found.")
            continue
            
        md5_asset = None
        zip_base_name = zip_asset['name'].replace('.zip', '')
        for a in assets:
            if a['name'].endswith('.md5') and zip_base_name in a['name']:
                md5_asset = a
                break

        checksum = ""
        if md5_asset:
            md5_content = fetch_text(md5_asset['browser_download_url'])
            if md5_content:
                checksum = md5_content.split()[0].strip()

        manifest_entry["versions"].append({
            "version": version_str,
            "changelog": release.get('body', ''),
            "targetAbi": target_abi,
            "sourceUrl": zip_asset['browser_download_url'],
            "checksum": checksum,
            "timestamp": release.get('published_at')
        })

    manifest_entry["versions"].sort(key=lambda x: x['timestamp'], reverse=True)

    manifest = [manifest_entry]

    with open('manifest.json', 'w') as f:
        json.dump(manifest, f, indent=4)
        
    print("Successfully generated manifest.json")

if __name__ == "__main__":
    main()
