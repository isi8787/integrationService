##Configure project for build

export GOPATH="$HOME/go"
export PATH="$PATH:$GOPATH/bin"
# Export the following go specific env vars to configure the tool chain so that I can clone
# repos from my private Bitbucket project.

export GOPRIVATE="bitbucket.org/carsonliving"

#configure git access
git config --global url."git@bitbucket.org:".insteadOf  https://bitbucket.org/
