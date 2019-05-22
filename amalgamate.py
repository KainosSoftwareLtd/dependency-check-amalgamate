import argparse
import json


def write_line(f, length, type):
    top_left_corner = '┌'
    top_right_corner = '┐'
    bottom_left_corner = '└'
    bottom_right_corner = '┘'
    horizontal_line = '─'
    edge = '│'
    line = ''

    for x in range(length):
        line += horizontal_line

    if type == 'top':
        f.write(f'{top_left_corner}{line}{top_right_corner}\n')
    elif type == 'bottom':
        f.write(f'{bottom_left_corner}{line}{bottom_right_corner}\n')
    else:
        f.write(f'{edge}{line}{edge}\n')


def write_name_value(f, length, name, value):
    column_one_width = 20
    padding = 2
    edge = '│'

    column_one = name
    for x in range(column_one_width - len(name)):
        column_one += ' '

    column_two = ' ' + value
    for x in range(length - (column_one_width + len(value) + padding)):
        column_two += ' '

    f.write(f'{edge}{column_one}{edge}{column_two}{edge}\n')


def write_vulnerability(f, vulnerability):
    name = vulnerability['name']
    evidence_count = vulnerability['evidence_count']
    project = vulnerability['project']
    highest_severity = vulnerability['highest_severity']
    vulnerability_count = vulnerability['vulnerability_count']
    line_length = 100

    write_line(f, line_length, 'top')
    write_name_value(f, line_length, 'Dependency', name)
    write_line(f, line_length, None)
    write_name_value(f, line_length, 'Evidence Count', str(evidence_count))
    write_line(f, line_length, None)
    write_name_value(f, line_length, 'Highest Severity', highest_severity)
    write_line(f, line_length, None)
    write_name_value(f, line_length, 'CVE Count', str(vulnerability_count))
    write_line(f, line_length, None)
    write_name_value(f, line_length, 'Project', project)
    write_line(f, line_length, 'bottom')


def severity_score(severity):
    if severity == '':
        return -1
    elif severity == 'Low':
        return 0
    elif severity == 'Medium':
        return 1
    elif severity == 'High':
        return 2


def read_dep_vulnerabilities(dependency):
    vulnerabilities = dependency.get('vulnerabilities', [])
    count = len(vulnerabilities)
    highest_severity = ''

    for vulnerability in vulnerabilities:
        severity = vulnerability['severity']
        if severity_score(severity) > severity_score(highest_severity):
            highest_severity = severity
    return count, highest_severity


def read_evidence_count(dependency):
    evidence = dependency['evidenceCollected']
    vendor_evidence = evidence['vendorEvidence']
    product_evidence = evidence['productEvidence']
    version_evidence = evidence['versionEvidence']
    return len(vendor_evidence) + len(product_evidence) + len(version_evidence)


def read_dependency(dependency):
    name = dependency['fileName']
    evidence_count = read_evidence_count(dependency)
    vulnerability_count, highest_severity = read_dep_vulnerabilities(dependency)
    return {'name': name,
            'evidence_count': evidence_count,
            'vulnerability_count': vulnerability_count,
            'highest_severity': highest_severity}


def filter_vulnerabilities(vulnerabilities):
    if type == 'both':
        return vulnerabilities

    filtered = []
    for vulnerability in vulnerabilities:
        if vulnerability['vulnerability_count'] > 0:
            filtered.append(vulnerability)
    return filtered


def sort_vulnerabilities(vulnerabilities):
    def severity_conversion(severity, vulnerability_count):
        if severity == 'High':
            return 300 + vulnerability_count
        elif severity == 'Medium':
            return 200 + vulnerability_count
        elif severity == 'Low':
            return 100 + vulnerability_count

    def sorting(a):
        return severity_conversion(a['highest_severity'], a['vulnerability_count'])

    return sorted(vulnerabilities, key=sorting, reverse=True)


def gather_vulnerabilities(data, project):
    vulnerability_data = []
    dependencies = data['dependencies']
    for dependency in dependencies:
        result = read_dependency(dependency)
        result['project'] = project
        vulnerability_data.append(result)

    return vulnerability_data


def write_vulnerabilities(f, vulnerabilities):
    for vulnerability in vulnerabilities:
        write_vulnerability(f, vulnerability)


def amalgamates(output, inputs):
    f = open(output, 'w')
    dependency_files = inputs.split(',')
    all_vulnerabilities = []
    for dependency_file in dependency_files:
        vulnerabilities = gather_vulnerabilities(json.loads(open(dependency_file).read()), dependency_file)
        all_vulnerabilities = all_vulnerabilities + vulnerabilities

    filtered_vulnerabilities = filter_vulnerabilities(all_vulnerabilities)
    sorted_vulnerabilities = sort_vulnerabilities(filtered_vulnerabilities)
    write_vulnerabilities(f, sorted_vulnerabilities)
    f.close()


parser = argparse.ArgumentParser()
parser.add_argument('output', help='Output file name')
parser.add_argument('inputs', help='Input audit files')
args = parser.parse_args()

amalgamates(args.output, args.inputs)

