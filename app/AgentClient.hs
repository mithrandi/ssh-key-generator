module Main (main) where

import Control.Applicative (pure, (<$>), (<*>))
import Data.Monoid ((<>))
import Options.Applicative (Parser, strOption, long, short, metavar, help, subparser, command, progDesc, info, execParser, helper, fullDesc, header)

data Options = Options
               { optCommand :: Command
               }

data Command = ListKeys ListOptions

data ListOptions = ListOptions

parseOptions :: Parser Options
parseOptions = Options
  <$> subparser (
    command "list-keys" (
       info listOptions (progDesc "List the keys currently available from the agent"))
    )
  where listOptions :: Parser Command
        listOptions = pure $ ListKeys ListOptions


main :: IO ()
main = execParser opts >>= run
  where opts = info (helper <*> parseOptions) (
          fullDesc
          <> progDesc "Simple SSH agent client"
          <> header "agent-client - a simple SSH agent client")
        run _ = undefined
