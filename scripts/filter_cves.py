import json
import argparse


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", help="file to write to", default="out.csv")
    parser.add_argument("-i", dest="input", help="JSON file to parse",
                        required=True)
    args = parser.parse_args()

    with open(args.input, 'r') as f:
        data = json.load(f)

    for cve in data['CVE_Items']:
        if cve['impact'].get('baseMetricV3') is None:
            continue

        if cve['impact']['baseMetricV3']['cvssV3']['baseScore'] >= 7.0:
            for node in cve['configurations']['nodes']:
                for cpematch in node['cpe_match']:
                    if cpematch['cpe23Uri'].lower().find('linux_kernel') \
                            >= 0:
                        print("{}\t{}".format(
                            cve['cve']['CVE_data_meta']['ID'],
                              cve['cve']['description'][
                                  'description_data'][0]['value']))
                        break


if __name__ == "__main__":
    main()
