## Service Control Policy (SCP) preprocessor

A command line tool that takes a single JSON file and outputs a collection of valid service control policies. This allows you to organize your SCPs logically and write statements in a way that makes sense to you without directly worrying about size constraints. The tool will then handle optimization and bin packing of your single JSON file into a collection of SCPs that fit the size limits.  The tool also introduces some new SCP language concepts that are explained below. The resultant SCPs are written to std out.

### Getting Started

Installation:

Python 3.6+ is supported.

```
pip install service-control-policy-preprocessor
```

Basic usage:
```bash
scp-pre process file://my-single-scp > output.json
```


### Available Commands

**process**

```bash
scp-pre process file://my-single-scp.json
```

| Arguments | Description |
| --------- |----------- |
| --enable-logging | Enables log output to stdout.  Turn off if you want to use the SCP output which is also output to stdout. |
| --retain-sid | Retain the SID element of the policy in the SCP output |
| --basic | Basic transformation. Skips the wildcarding of IAM actions that outputs the shortest possible action prefix to save space. |
| --pretty-print | Keep whitespace to make output readable. Useful for debugging. |


### New language constructs for IAM actions

#### Exclude a particular action from the resulting action list

Must be an exact action name, does not support globbing. Useful when there are only a few exemptions.

Example:

```json
{
  ...
  "Action": [
    "iam:*User*",
    "iam:{Exclude:ListUsers}"
  ]
}
```

Resulting SCP will contain all actions matching `iam:*User*` except for iam:ListUsers.

#### Adds support for wildcards in all parts of IAM action name

Example:

```json
{
  ...
  "Action": [
    "service:*PartOfActionName*"
  ]
}
```

Regular SCP syntax only supports wildcards at the end of the action name. The resulting SCP will have all actions that match this wildcard pattern expanded.

#### Adds support for comment element in SCPs

Example:

```json
{
  ...
  "Action": [
    "service:Action"
  ],
  "Comment": "This will be stripped off before deployment, but can be helpful when left in a source repository."
}
```

Comments are stripped during preproccessing. This is a helpful place to store a short explanation of the policy statement.

### Transformations that are done to your SCP (in order)

1. SIDs and Comments are removed from all statements
2. Wildcards are expanded
3. Actions are excluded if using the {Exclude} syntax
4. Statements with the same Effect, Resource, and Condition are merged together
5. Actions are wildcarded to save space. This can be disabled with the `--basic` flag.
   1. Example: iam:SetSecurityTokenServicePreferences -> iam:SetS*
   2. You will want to run this transformation periodically (e.g. daily) if you use this feature. This is because new IAM actions are added over time that the transformation has not taken into account when shortening these action names.
6. Statements are bin packed to fit SCP size quotas


## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

