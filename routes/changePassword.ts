/*
 * Copyright (c) 2014-2025 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'
import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import { UserModel } from '../models/user'
import * as security from '../lib/insecurity'
import bcrypt from 'bcrypt' 

export function changePassword () {
  return async ({ query, headers, connection }: Request, res: Response, next: NextFunction) => {
    const currentPassword = query.current as string
    const newPassword = query.new as string
    const newPasswordInString = newPassword?.toString()
    const repeatPassword = query.repeat

    if (!newPassword || newPassword === 'undefined') {
      res.status(401).send(res.__('Password cannot be empty.'))
      return
    } else if (newPassword !== repeatPassword) {
      res.status(401).send(res.__('New and repeated password do not match.'))
      return
    }

    const token = headers.authorization ? headers.authorization.substr('Bearer='.length) : null
    if (token === null) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }

    const loggedInUser = security.authenticatedUsers.get(token)
    if (!loggedInUser) {
      next(new Error('Blocked illegal activity by ' + connection.remoteAddress))
      return
    }

    try {
      const user = await UserModel.findByPk(loggedInUser.data.id)
      if (!user) {
        res.status(404).send(res.__('User not found.'))
        return
      }
 if (currentPassword) {
    const passwordMatch: boolean = await bcrypt.compare(currentPassword, user.password)
    if (!passwordMatch) {
      res.status(401).send(res.__('Current password is not correct.'))
      return
    }
  }
      const hashedPassword: string = await bcrypt.hash(newPasswordInString, 10)
      await user.update({ password: hashedPassword })
      challengeUtils.solveIf(
        challenges.changePasswordBenderChallenge,
        async () => user.id === 3 && !currentPassword && await bcrypt.compare('slurmCl4ssic', user.password)
      )

      res.json({ user })
    } catch (error) {
      next(error)
    }
  }
}
